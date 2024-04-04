function getepoch(date1) {
    var epochdate = new Date("01/01/1999")
    var curdate = new Date(date1)

    var Difference_In_Time = curdate.getTime() - epochdate.getTime();
    var daydelta = Math.floor(Difference_In_Time/ (1000 * 3600 * 24))
    //console.log(daydelta)
    return daydelta
}
function getformval(eleid) {
    var el = document.getElementById(eleid)
    return el.value
}

function cooktext(text1) {
    var retval = text1.toUpperCase().replace("/n","").replace(" ","").replace("/t", "").replace("/r","")
    return retval
}


function getkey() {
    //var regnameele = document.getElementById("RegName")
    //console.log(txtbox.value)
    //get hwid value and remove dashes
    var hwidstr = ("0x" + getformval("HWID1")).replace("-","")

    var del1 = getepoch(getformval("dateepoch"))
    var time = Number(del1) << 16
    var hwid = Number(hwidstr)
    var symkey = 0x52083B70
    var keya = (symkey ^ hwid) >>> 0
    var keyahex = ('00000000' + keya.toString(16)).slice(-8)
    console.log(keyahex)
    var timehex = ('00000000' + time.toString(16)).slice(-8)
    var keyb = keyahex + timehex
    //console.log(keyb)
    var regname = getformval("RegName")
    var key4 = cooktext(regname)
    var res1 = blowfish.decrypt(keyb, key4, {cipherMode: 0, outputType: 1});
    var res2 = res1.toUpperCase()
    var finkeya = res2.substring(0,4) + "-" + res2.substring(4,8) + "-" + res2.substring(8,12) + "-" + res2.substring(12,16)
    var finkeyele = document.getElementById("finkey")
    finkeyele.innerText = finkeya
}


window.addEventListener("DOMContentLoaded", (event) => {
    var curcurdate = new Date()
    var el = document.getElementById("dateepoch")
    el.value = curcurdate.toISOString().split('T')[0]
    var el2 = document.getElementById("getkeybutton")
    el2.addEventListener("click", getkey)
})

    
