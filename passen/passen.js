function getformval(eleid) {
    var el = document.getElementById(eleid)
    return el.value
}

function sendtxt() {
		var inputxt = getformval("sendtxt");
		var inputip = getformval("ipadr")
		var encodedtxt = window.btoa(inputxt).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		var sendimg = document.createElement("img");
		var sendsrc = "http://" + inputip + ":8000/" + encodedtxt
		sendimg.src = sendsrc
		var finkeyele = document.getElementById("test1234ele");
		finkeyele.appendChild(sendimg)// = encodedtxt;
}

function decodetxt() {
	var inputxt = getformval("sendtxt");
	var encodedtxt = window.atob(inputxt.replace(/\-/g, '+').replace(/\_/g, '/'));
	alert(encodedtxt)
}


function decodeButtonClicked() {
	//alert("hello");
	isdecode = true
	document.getElementById("ipadr").style.display = "none";
	document.getElementById("ip2").style.display = "none";
	document.getElementById("ip3").style.display = "none";
	document.getElementById("txttochg").innerText = "Text2Decode"
}

function encodeButtonClicked() {
	//alert("hello");
	isdecode = false
	document.getElementById("ipadr").style.display = "";
	document.getElementById("ip2").style.display = "";
	document.getElementById("ip3").style.display = "";
	document.getElementById("txttochg").innerText = "Text2send"
}

function procinput() {
	if (isdecode) {
		decodetxt()
	} else {
		sendtxt()
	}
}

window.addEventListener("DOMContentLoaded", (event) => {
	document.getElementById("sendtxtbtnbutton").addEventListener("click", procinput);
	document.getElementById("opt2").addEventListener("click", decodeButtonClicked);
	document.getElementById("opt1").addEventListener("click", encodeButtonClicked);
})

var isdecode = false