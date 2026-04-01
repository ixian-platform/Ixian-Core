/*! Ixian Core | MIT License | github.com/ixian-platform/Ixian-Core */

var primaryAddress = null;

var qrcode = null;

var selectedReceiveAddress = null;

function copyToClipboard(addr) {
    navigator.clipboard.writeText(addr)
        .then(() => {
            const el = document.getElementById("selectedReceiveAddress");
            el.classList.add("copied");

            // Remove the class after animation
            setTimeout(() => el.classList.remove("copied"), 800);
        })
        .catch(err => console.error("Copy failed", err));
}

function setReceiveAddress(address) {
    selectedReceiveAddress = address;

    document.getElementById("selectedReceiveAddress").innerHTML = selectedReceiveAddress;

    // Create the QR code
    qrcode.clear();
    qrcode.makeCode(selectedReceiveAddress);

    copyToClipboard(address);
}

function getMyWallet() {

    $.getJSON("gettotalbalance", {})
        .done(function (data) {
            data = data["result"];

            // Assign relevant wallet information
            document.getElementById("activity_balance_number").innerHTML = data;
            document.getElementById("send_balance_number").innerHTML = data;

        });

    $.getJSON("mywallet", {})
        .done(function (data) {
            data = data["result"];
            var keyList = Object.keys(data);
            if (selectedReceiveAddress == null) {
                primaryAddress = selectedReceiveAddress = keyList[keyList.length - 1];
                // Create the QR code
                qrcode.clear();
                qrcode.makeCode(selectedReceiveAddress);
            }

            var html = "<div id=\"selectedReceiveAddress\" onclick=\"copyToClipboard('" + selectedReceiveAddress + "');\">" + selectedReceiveAddress + "</div>";

            if (keyList.length > 1) {
                html += "<div class=\"dropDown\">";
                var first = true;
                for (var i in data) {
                    var primaryDesignator = "";
                    if (first) {
                        primaryAddress = i;
                        primaryDesignator = " - Primary Address";
                        first = false;
                    }
                    html += "<span onclick=\"setReceiveAddress('" + i + "');\" class=\"" + (primaryDesignator != "" ? "primary" : "") + "\">" + i + " (" + data[i] + ")" + primaryDesignator + "</span><br/>";
                }

                html += "</div>";
            }
            // Assign relevant wallet information
            document.getElementById("receive_own_address").innerHTML = html;

        });
}

function statusToString(status, type) {
    switch (status) {
        case 1:
            return "Pending";
        case 2:
            return "Final";
        case 3:
            if (type == 200) {
                return "Discarded";
            }
            return "Error";
        case 4:
            return "Reverted";
        default:
            return "Unknown - " + status;
    }
}


function statusToClassName(status) {
    switch (status) {
        case 1:
            return "pending";
        case 2:
            return "final";
        case 3:
            return "error";
        case 4:
            return "reverted";
        default:
            return "error";
    }
}

function jsonToHtml(jsonArr) {
    var html = "";
    for (var key in jsonArr) {
        html += "<b>" + key + "</b>: " + jsonArr[key] + "<br/>";

    }
    return html;
}

function addressListToString(jsonArr, includeAmounts) {
    var html = "";
    for (var key in jsonArr) {
        if (html != "") {
            html += ", ";
        }
        if (includeAmounts) {
            html += key + ": " + jsonArr[key];
        } else {
            html += key;
        }
    }
    return html;
}

function getActivity() {
    var activity_type_el = document.getElementById("activity_type");
    $.getJSON("activity2?type=" + activity_type_el.options[activity_type_el.selectedIndex].value + "&descending=true", {})
        .done(function (data) {
            document.getElementById("payments").innerHTML = "";
            for (var i in data["result"]) {
                var paymentsEl = document.getElementById("payments");
                paymentsEl.innerHTML += document.getElementById("templates").getElementsByClassName("payment")[0].outerHTML;
                var htmlEl = paymentsEl.lastElementChild;

                htmlEl.getElementsByClassName("pdesc")[0].innerHTML = addressListToString(data["result"][i]["addressList"], false);

                data["result"][i]["addressList"] = addressListToString(data["result"][i]["addressList"], true);
                htmlEl.getElementsByClassName("pdetails")[0].innerHTML = jsonToHtml(data["result"][i]);

                var type = data["result"][i]["type"];
                if (type == 100) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Payment Received";
                } else if (type == 101) {
                    htmlEl.className += " sent";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = "-" + data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Payment Sent";
                } else if (type == 200) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Mining Reward";
                } else if (type == 201) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Signing Reward";
                } else if (type == 202) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Transaction fee Reward";
                } else if (type == 400) {
                    htmlEl.className += " sent";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>IXI Names";
                }
                var date = new Date(data["result"][i]["timestamp"] * 1000);
                htmlEl.getElementsByClassName("pamount")[0].innerHTML += "<br/><span class=\"pdate\">" + date.toLocaleString() + "</span>";
                var status = statusToString(data["result"][i]["status"], type);
                htmlEl.getElementsByClassName("pdesc")[0].innerHTML += " - " + status;
                var statusClassName = statusToClassName(data["result"][i]["status"]);
                htmlEl.className += " " + statusClassName;
            }
        });
}

function sendTransaction() {

    var dltAPI = "addtransaction?to=";

    var addressEls = document.getElementsByName("address");
    var amountEls = document.getElementsByName("amount");
    for (var i = 0; i < addressEls.length; i++) {
        if (i > 0) {
            dltAPI += "-";
        }

        var amount = amountEls[i];
        if (amount == null || amount.value.trim() <= 0) {
            alert("Incorrect amount specified.");
            return;
        }

        dltAPI += addressEls[i].value.trim() + "_" + amount.value.trim();
    }

    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            if (data["result"] != null) {
                getMyWallet();
                alert("Transaction successfully sent. txid: " + data["result"]["id"]);
            } else {
                alert("An error occurred while trying to send a transaction: (" + data["error"]["code"] + ") " + data["error"]["message"]);
            }
        })
        .fail(function (jqXHR, status, error) {
            let data = JSON.parse(jqXHR.responseText);
            alert("An error occurred while trying to send a transaction: (" + data["error"]["code"] + ") " + data["error"]["message"]);
        });

}

function generateNewAddress() {
    var dltAPI = "generatenewaddress";
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            selectedReceiveAddress = data["result"];
            qrcode.clear();
            qrcode.makeCode(selectedReceiveAddress);
            getMyWallet();
        });

}

function setBlockSelectionAlgorithm(algorithm) {
    var dltAPI = "setBlockSelectionAlgorithm?algorithm=" + algorithm;
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            getStatus();
        });

}

function calculateTransactionAmounts() {
    var dltAPI = "createrawtransaction?to=";

    var addressEls = document.getElementsByName("address");
    var amountEls = document.getElementsByName("amount");
    var totalAmount = 0;
    for (var i = 0; i < addressEls.length; i++) {
        if (i > 0) {
            dltAPI += "-";
        }

        var amount = amountEls[i];
        if (amount == null || amount.value.trim() <= 0) {
            continue;
        }

        totalAmount += parseFloat(amount.value.trim());

        dltAPI += addressEls[i].value.trim() + "_" + amount.value.trim();
    }
    dltAPI += "&json=true";
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            if (data["result"] != null) {
                document.getElementById("transactionFee").innerHTML = (parseFloat(data["result"]["totalAmount"]) - totalAmount).toFixed(8);
                document.getElementById("totalAmount").innerHTML = data["result"]["totalAmount"];
            } else {
                // fail
            }
        });

}
function showSyncProgress(percent, text = "Syncing blockchain...") {
    const bar = document.getElementById('warning_bar');
    const label = document.getElementById('warning_text');
    const percentLabel = document.getElementById('warning_percent');
    const fill = document.getElementById('warning_progress_fill');
    const warningOther = document.getElementById('warning_other');
    const warningSync = document.getElementById('warning_sync');

    label.textContent = text;
    percentLabel.textContent = percent + "%";
    fill.style.width = percent + "%";

    warningOther.style.display = "none";
    warningSync.style.display = "block";
}

function getStatus() {

    var dltAPI = "status";
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            document.getElementById("version").innerHTML = data["result"]["Node Version"] + " (" + data["result"]["Core Version"] + ") BETA";

            sync_status = data["result"]["DLT Status"];

            const warningOther = document.getElementById('warning_other');
            const warningSync = document.getElementById('warning_sync');
            warningOther.style.display = "block";
            warningSync.style.display = "none";

            var warning_bar = document.getElementById("warning_bar");
            warning_bar.style.display = "block";

            if (sync_status == "Synchronizing") {
                // Show the syncbar
                showSyncProgress(data["result"]["Block Height"] / data["result"]["Network Block Height"], "Synchronizing the blockchain, block #" + data["result"]["Block Height"] + " / " + data["result"]["Network Block Height"] + ".")

            } else if (sync_status == "ErrorForkedViaUpgrade") {
                warning_bar.firstElementChild.innerHTML = "Network has been upgraded, please download a newer version of Ixian DLT.";
            } else if (sync_status == "ErrorLongTimeNoBlock") {
                warning_bar.firstElementChild.innerHTML = "No fully signed block received for a while, make sure that you're connected to the internet.";
            }
            else {
                // Hide the syncbar
                warning_bar.style.display = "none";
                warning_bar.firstElementChild.innerHTML = "";
            }

            var network_time_diff = data["result"]["Network time difference"];
            var real_network_time_diff = data["result"]["Real network time difference"];

            if (data["result"]["Network Servers"] > 2 && network_time_diff != real_network_time_diff) {
                warning_bar.style.display = "block";
                if (warning_bar.firstElementChild.innerHTML != "") {
                    warning_bar.firstElementChild.innerHTML += "<br/>";
                }
                warning_bar.firstElementChild.innerHTML += "Please make sure that your computer's date and time are correct.";
            }

            var node_type = data["result"]["Node Type"];
            if ((node_type == "M" || node_type == "H")
                && data["result"]["Network Servers"] == "[]") {
                if (data["result"]["Connectable"] == false) {
                    warning_bar.style.display = "block";
                    if (warning_bar.firstElementChild.innerHTML != "") {
                        warning_bar.firstElementChild.innerHTML += "<br/>";
                    }
                    warning_bar.firstElementChild.innerHTML += "This node is not connectable from the internet and other nodes can't connect to it. Please set-up port-forwarding.";
                }
            }

            if (data["result"]["Update"] != "" && data["result"]["Update"] != undefined) {
                warning_bar.style.display = "block";
                if (warning_bar.firstElementChild.innerHTML != "") {
                    warning_bar.firstElementChild.innerHTML += "<br/>";
                }
                warning_bar.firstElementChild.innerHTML += "An updated version of Ixian node (" + data["result"]["Update"] + ") is available, please visit https://www.ixian.io";
            }
        });

    var dltAPI = "minerstats";
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            if (data["result"]) {
                var status = "Disabled";
                if (data["result"]["Hashrate"] > 0) {
                    status = "Mining";
                } else {
                    status = "Paused";
                }
                var minerEl = document.getElementById("MinerSection");
                minerEl.style.display = "block";
                var html = "Miner: " + status + "<br/>";
                html += "Rate: " + data["result"]["Hashrate"] + "<br/>";
                html += "Algorithm: " + data["result"]["Search Mode"] + "<br/>";
                html += "<div class=\"dropDown\">";
                html += "<span onclick=\"setBlockSelectionAlgorithm(-1);\">Disable</span><br/>";
                html += "<span onclick=\"setBlockSelectionAlgorithm(0);\">Lowest Difficulty</span><br/>";
                html += "<span onclick=\"setBlockSelectionAlgorithm(1);\">Random Lowest Difficulty</span><br/>";
                html += "<span onclick=\"setBlockSelectionAlgorithm(2);\">Latest Block</span><br/>";
                html += "<span onclick=\"setBlockSelectionAlgorithm(3);\">Random</span><br/>";
                html += "</div>";
                minerEl.innerHTML = html;
            } else {
                document.getElementById("MinerSection").style.display = "none";
            }
        })
        .fail(function (jqXHR, status, error) {
            document.getElementById("MinerSection").style.display = "none";
        });

}

var html5QrCode = null;
function readQR(addressEl) {
    document.getElementById('reader_modal').style.display = 'block';
    if (html5QrCode != null) {
        return;
    }
    console.log("Starting QR code reader");

    html5QrCode = new Html5Qrcode(
        "reader", { formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE] });
    const qrCodeSuccessCallback = (decodedText, decodedResult) => {
        console.log("QRscanner: " + decodedText);
        addressEl.value = decodedText;
        closeQR();
    };
    const config = {
        fps: 15,
        qrbox: 450,
        showTorchButtonIfSupported: true,
        focusMode: "continuous",
        showZoomSliderIfSupported: true,
        supportedScanTypes: [Html5QrcodeScanType.SCAN_TYPE_CAMERA]
    };

    html5QrCode.start({ facingMode: "environment" }, config, qrCodeSuccessCallback);

    setTimeout(function () {
        html5QrCode.applyVideoConstraints({
            focusMode: "continuous",
            advanced: [{ zoom: 2.0 }],
        });
    }, 1000);
}

function stopQR() {
    if (html5QrCode == null) {
        return;
    }
    html5QrCode.stop();
    html5QrCode = null;
}

function closeQR() {
    document.getElementById('reader_modal').style.display = 'none';
    stopQR();
}

function addRecipient() {
    var div = document.createElement("div");
    div.className = "recipient-card";
    div.innerHTML = document.getElementsByClassName("recipient-card")[0].innerHTML;

    document.getElementById("sendSection").appendChild(div);
}

function switchTab(e, tabId) {
    e.preventDefault();

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.bottom-nav a').forEach(a => a.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');
    e.target.classList.add('active');
}


$(function () {
    console.log("Wallet loaded");

    $('#sendForm').submit(function () {
        sendTransaction();
        return false;
    });

    qrcode = new QRCode(document.getElementById("qrcode"), {
        width: 300,
        height: 300
    });

    setInterval(getMyWallet, 5000);
    setInterval(getActivity, 5000);
    setInterval(getStatus, 5000);
    getMyWallet();
    getActivity();
    getStatus();
});

function signMessage() {
    const message = $("#sign_message").val();
    const wallet = $("#sign_address").val();
    let params = {
        message: message
    };

    if (wallet != null) {
        let params = {
            wallet: wallet,
            message: message
        };
    }

    if (!message) {
        alert("Enter message");
        return;
    }

    $.ajax({
        url: "/sign",
        method: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            method: "sign",
            params: params,
            id: 1
        }),
        success: function (res) {
            if (res && res.result) {
                $("#sign_public_key").val(res.result.publicKey);
                $("#sign_output").val(res.result.signature);
            } else {
                alert("Signing failed");
            }
        },
        error: function (err) {
            console.error(err);
            alert("RPC error");
        }
    });
}

function verifyMessage() {
    const message = $("#verify_message").val();
    const publicKey = $("#verify_public_key").val();
    const signature = $("#verify_signature").val();

    if (!message || !publicKey || !signature) {
        alert("Fill all fields");
        return;
    }

    $.ajax({
        url: "/verify",
        method: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            method: "verify",
            params: {
                publicKey: publicKey,
                signature: signature,
                message: message
            },
            id: 1
        }),
        success: function (res) {

            if (res) {
                const valid = res.result.verified === "ok";
                $("#verify_result")
                    .text(valid ? "✔ Valid signature (Address: " + res.result.address + ")" : "✖ Invalid signature (Address: " + res.result.address + ")")
                    .css("color", valid ? "green" : "red");
            } else {
                alert("Verification failed");
            }
        },
        error: function (err) {
            console.error(err);
            $("#verify_result")
                .text("✖ Invalid signature")
                .css("color", "red");
        }
    });
}
