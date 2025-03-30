/*! Ixian Core | MIT License | github.com/ProjectIxian/Ixian-Core */

var primaryAddress = null;

var qrcode = null;

var selectedReceiveAddress = null;

// copyToClipboard function copied from https://hackernoon.com/copying-text-to-clipboard-with-javascript-df4d4988697f
const copyToClipboard = str => {
    const el = document.createElement('textarea');  // Create a <textarea> element
    el.value = str;                                 // Set its value to the string that you want copied
    el.setAttribute('readonly', '');                // Make it readonly to be tamper-proof
    el.style.position = 'absolute';
    el.style.left = '-9999px';                      // Move outside the screen to make it invisible
    document.body.appendChild(el);                  // Append the <textarea> element to the HTML document
    const selected =
        document.getSelection().rangeCount > 0        // Check if there is any content selected previously
            ? document.getSelection().getRangeAt(0)     // Store selection if found
            : false;                                    // Mark as false to know no selection existed before
    el.select();                                    // Select the <textarea> content
    document.execCommand('copy');                   // Copy - only works as a result of a user action (e.g. click events)
    document.body.removeChild(el);                  // Remove the <textarea> element
    if (selected) {                                 // If a selection existed before copying
        document.getSelection().removeAllRanges();    // Unselect everything on the HTML document
        document.getSelection().addRange(selected);   // Restore the original selection
    }
};

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
                    html += "<span onclick=\"setReceiveAddress('" + i + "');\">" + i + " (" + data[i] + ")" + primaryDesignator + "</span><br/>";
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
        default:
            return "Unknown - " + status;
    }

}

function jsonToHtml(jsonArr)
{
    var html = "";
    for (var key in jsonArr)
    {
        html += "<b>" + key + "</b>: " + jsonArr[key] + "<br/>";

    }
    return html;
}

function getActivity() {
    var activity_type_el = document.getElementById("activity_type");
    $.getJSON("activity?type=" + activity_type_el.options[activity_type_el.selectedIndex].value + "&descending=true", {})
        .done(function (data) {
            document.getElementById("payments").innerHTML = "";
            for (var i in data["result"]) {
                var paymentsEl = document.getElementById("payments");
                paymentsEl.innerHTML += document.getElementById("templates").getElementsByClassName("payment")[0].outerHTML;
                var htmlEl = paymentsEl.lastElementChild;
                htmlEl.getElementsByClassName("pdesc")[0].innerHTML = data["result"][i]["toList"];

                htmlEl.getElementsByClassName("pdetails")[0].innerHTML = jsonToHtml(data["result"][i]);

                var type = data["result"][i]["type"];
                if (type == 100) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML = data["result"][i]["from"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Payment Received";
                } else if (type == 101) {
                    htmlEl.className += " sent";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = "-" + data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Payment Sent";
                } else if (type == 200) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML = data["result"][i]["from"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Mining Reward";
                } else if (type == 201) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML = data["result"][i]["wallet"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Signing Reward";
                } else if (type == 202) {
                    htmlEl.className += " received";
                    htmlEl.getElementsByClassName("pamount")[0].innerHTML = data["result"][i]["value"];
                    htmlEl.getElementsByClassName("pdesc")[0].innerHTML += "<br/>Transaction fee Reward";
                }
                var date = new Date(data["result"][i]["timestamp"] * 1000);
                htmlEl.getElementsByClassName("pamount")[0].innerHTML += "<br/><span class=\"pdate\">" + date.toLocaleString() + "</span>";
                var status = statusToString(data["result"][i]["status"], type);
                htmlEl.getElementsByClassName("pdesc")[0].innerHTML += " - " + status;
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
        if (amount == null || amount.value.trim() <= 0)
        {
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
    for (var i = 0; i < addressEls.length; i++) {
        if (i > 0) {
            dltAPI += "-";
        }

        var amount = amountEls[i];
        if (amount == null || amount.value.trim() <= 0) {
            continue;
        }

        dltAPI += addressEls[i].value.trim() + "_" + amount.value.trim();
    }
    dltAPI += "&json=true";
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            if (data["result"] != null) {
                document.getElementById("transactionFee").innerHTML = data["result"]["fee"];
                document.getElementById("totalAmount").innerHTML = data["result"]["totalAmount"];
            } else {
                // fail
            }
        });

}

function getStatus() {

    var dltAPI = "status";
    $.getJSON(dltAPI, { format: "json" })
        .done(function (data) {
            document.getElementById("version").innerHTML = data["result"]["Node Version"] + " (" + data["result"]["Core Version"] + ") BETA";

            sync_status = data["result"]["DLT Status"];

            var warning_bar = document.getElementById("warning_bar");
            warning_bar.style.display = "block";

            if (sync_status == "Synchronizing") {
                // Show the syncbar
                warning_bar.firstElementChild.innerHTML = "Synchronizing the blockchain, block #" + data["result"]["Block Height"] + " / " + data["result"]["Network Block Height"] + ".";

            } else if (sync_status == "ErrorForkedViaUpgrade")
            {
                warning_bar.firstElementChild.innerHTML = "Network has been upgraded, please download a newer version of Ixian DLT.";
            } else if (sync_status == "ErrorLongTimeNoBlock")
            {
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
                var html = "Miner: " + status;
                html += " Rate: " + data["result"]["Hashrate"] + "<br/>";
		html += "Current block: " + data["result"]["Current Block"] + "<br/>";
                html += "Found blocks: " + data["result"]["Solved Blocks (Local)"] + " (" + data["result"]["Last Solved Block Time"] + ")<br/>";
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
        });

}

function readQR(addressEl) {
    console.log("Starting QR code reader");

    let scanner = new Instascan.Scanner({});
    scanner.addListener('scan', function (content) {
        console.log("QRscanner: " + content);
        addressEl.innerHTML = content;
    });
    Instascan.Camera.getCameras().then(function (cameras) {
        if (cameras.length > 0) {
            scanner.start(cameras[0]);
        } else {
            console.error('No cameras found.');
            alert("No camera found. Please type the address to send funds to.");
        }
    }).catch(function (e) {
        console.error(e);
    });

}

function addRecipient() {
    var div = document.createElement("div");
    div.className = "single_send_section";
    div.innerHTML = document.getElementsByClassName("single_send_section")[0].innerHTML;

    document.getElementById("sendSection").appendChild(div);
}

function initTabs()
{
    // Function to toggle tab's active color
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        var nodes = document.getElementById("bottomNav").childNodes;
        for(var childIndex = 0; childIndex < nodes.length; childIndex++)
        {
            if(nodes[childIndex].nodeName.toLowerCase() != "div")
            {
                continue;     
			}
            nodes[childIndex].className = nodes[childIndex].className.replace("active", "").trim();
        }
        e.target.parentElement.className += " active";
    });
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

    initTabs();
    setInterval(getMyWallet, 5000);
    setInterval(getActivity, 5000);
    setInterval(getStatus, 5000);
    getMyWallet();
    getActivity();
    getStatus();
});
