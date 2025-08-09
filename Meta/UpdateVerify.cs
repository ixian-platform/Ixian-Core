// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace IXICore.Meta
{
    public class UpdateVerify
    {
        private static Thread updateVerifyThread;
        private static bool running = false;

        public static int checkInterval = 6 * 60 * 60;

        public static string signPubKey = "<RSAKeyValue><Modulus>uoqtGaAoQBTkZUuxuBsusUsHYb5sy0iYJPuE+zhM9ZMySCQK3PevZvhqj9bdEv82A/cl0lYWTWk9ZU2sLAm1n6DLFwCwC8AWShv3Il8y8L4oCbDMfyBWMY9yPq5XSQnplrfR5rER/MWt+XQX/cJeEOd0prNgIYSPluo7u+h+fM2CzMfv5vFtN/E1HSxKUVhP8wkGmOoxXo1EfIqzEHlg4BO0z+hNEIdiXopvwOVkDbetWnOXnwOkOC+bcvPWFP3RYfFiez7GStJFVJhs1lc7wM3PmotzoO7/4NyuxVueydRBERhGbq+KV0FfggPshMh/+srpbu6etiLyW7KtZX8ARgxasZVHNggIRygM4LYLk/ppcvHCohEfmYsrTo1Bk0CQe1JFIbFIWXLK+5VDhpVc0w1HpeyjuB/fL8vEHBhOfuNL8frhfpFWTzzPF2IBd59E6T8TQCM/K2DBuxWAEws8nqcNpYsjocuRw2OZmbjzPcerCo2haVaezT3YbNZHAflzSxI+VmURyuXBw+76IV63gJTwGWpZ4A+/D6ubOuqrssfTBRYdjJLTecb3D7aBd2JpKVPVfSN61zSrkt++eEgkikkFVSqQ2ILGB7azzaGPCm4RL0ZMa47BSfMcPSMM4oN91mbVWSWaspCQe0TjbeIR9jl18Y1jcvHloiX8rVC5YKWPPYG8YuGcKq8U0Hp2lkeCnXqKfvUGoH/e6ufkwBCqJZle2S+wmRHKFlEuMHxs1sUEgleZcnQQ6lXYuwpoIXKB6NxMrSTPWM+QHWVnU0tL0X3MYIvCxT6olYV1H9Rfrm3p9lP1vJME7H0sudypXlsUzddMQtqLAjpS7Sgl1RJ7CwnYQa/nfrMYokaWhXdHeT0XpdANyiRdlklrHE19Jlb4Z/wpK+P4zYfrx/8Mj6J+ktxJuyHQVj1wVwH9qmsWfVvwJ4xPKBQcfS4aJ6iUnGwY1HuywETGgx4eAp4vsVjaR7VCE/JPA4kwLCKAcXAT2BwNMC3rCG+4XouyZuZjYLGGTuRkqpXQ1mTBKXSg6t9iUsc25V9k4jS1d+y7qumDT6jqsLavvvwkBKpu1ONgew9Pqbc9GLXBmXSHIhUdFiFF9d3cvWv5m3QhRKdCW0jQ8xUAlxgZW27a+09YppVwvex6/8fmhx9nldpC1I24EyyrBXWgIABAvxv0gAo0CzPTLIOh1c8oOapMaie2aAR3Epfna+q/Z/h5ofrx9HmP+xAxhKHOHrRWo+EybceoWh/mmMRjnqmm1G4DrHsW90Z56qZWdX4QGMXpP9ZhVvxqFj1IxWkzOHk5XAOq44UQq2hFT46bAbe+s5JSOGfvMzzagFC5LuuAeelFTUfRR7wFClM5kQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public static string updateUrl = null;

        public static string serverVersion { get; private set; } = "";
        /// <summary>
        ///  Version string is ready in `serverVersion`.
        /// </summary>
        public static bool ready { get; private set; } = false;
        /// <summary>
        ///  There was an error while fetching version information, or it was signed incorrectly.
        /// </summary>
        public static bool error { get; private set; } = false;

        public static void init(string url, int check_interval, string sign_pub_key = null)
        {
            updateUrl = url;
            checkInterval = check_interval;
            if(sign_pub_key != null)
            {
                signPubKey = sign_pub_key;
            }
        }

        public static bool start()
        {
            if(running)
            {
                Logging.error("UpdateVerify is already running.");
                return false;
            }

            if (updateUrl == null)
            {
                Logging.error("Cannot check version, URL is null");
                return false;
            }

            running = true;

            ready = false;
            error = false;
            serverVersion = "";

            updateVerifyThread = new Thread(updateVerifyLoop);
            updateVerifyThread.Name = "Update_Verify_Thread";
            updateVerifyThread.IsBackground = true;
            updateVerifyThread.Start();

            return true;
        }

        public static bool stop()
        {
            if (!running)
            {
                Logging.error("UpdateVerify is already stopped.");
                return false;
            }

            running = false;

            // Force stopping of thread
            if (updateVerifyThread == null)
                return true;

            updateVerifyThread.Interrupt();
            updateVerifyThread.Join();
            updateVerifyThread = null;

            return true;
        }

        private static void updateVerifyLoop()
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    while (running)
                    {
                        try
                        {
                            var response = client.GetStringAsync(updateUrl).Result;
                            string[] update_strings = response.Split(';');
                            string version_text = update_strings[0];
                            string signature = update_strings[1];
                            if (!checkSignature(version_text, signature))
                            {
                                throw new Exception("Incorrect signature for the retrieved version text!");
                            }
                            serverVersion = version_text;
                            error = false;
                        }
                        catch (ThreadInterruptedException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            Logging.warn("Error while checking {0} for version update: {1}", updateUrl, ex.Message);
                            serverVersion = "";
                            error = true;
                        }
                        finally
                        {
                            ready = true;
                        }

                        Thread.Sleep(checkInterval * 1000);
                    }
                }
            }
            catch (ThreadInterruptedException)
            {

            }
            catch (Exception e)
            {
                Logging.error("UpdateVerify exception: {0}", e);
            }
        }


        private static bool checkSignature(string version, string base64Sig)
        {
            byte[] signature_bytes = Convert.FromBase64String(base64Sig);
            byte[] version_bytes = Encoding.ASCII.GetBytes(version);
            RSACryptoServiceProvider r = new RSACryptoServiceProvider();
            r.FromXmlString(signPubKey);
            return r.VerifyData(version_bytes, signature_bytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public static int compareVersionsWithSuffix(string v1, string v2)
        {
            // Helper to split into numeric and suffix parts
            (string numericPart, string suffix) splitVersion(string v)
            {
                int index = 0;
                // Find where suffix starts (first non-digit/dot character)
                while (index < v.Length && (char.IsDigit(v[index]) || v[index] == '.'))
                    index++;
                return (v.Substring(0, index), v.Substring(index));
            }

            var (num1, suf1) = splitVersion(v1);
            var (num2, suf2) = splitVersion(v2);

            if (Version.TryParse(num1, out var ver1) && Version.TryParse(num2, out var ver2))
            {
                int cmp = ver1.CompareTo(ver2);
                if (cmp != 0)
                    return cmp;

                // Numeric parts are equal, so compare suffixes
                if (string.IsNullOrEmpty(suf1))
                {
                    if (!string.IsNullOrEmpty(suf2))
                    {
                        if (!suf2.StartsWith('-'))
                        {
                            return -1; // suffix means higher version, so suf2 > suf1
                        }
                        else
                        {
                            return 1;
                        }
                    }
                }
                if (string.IsNullOrEmpty(suf2))
                {
                    if (!string.IsNullOrEmpty(suf1))
                    {
                        if (!suf1.StartsWith('-'))
                        {
                            return 1;  // suf1 > suf2
                        }
                        else
                        {
                            return -1;
                        }
                    }
                }
                    
                return string.Compare(suf1, suf2, StringComparison.Ordinal);
            }

            // Fallback to string compare if parse fails
            return string.Compare(v1, v2, StringComparison.Ordinal);
        }
    }
}
