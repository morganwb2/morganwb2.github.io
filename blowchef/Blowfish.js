/* 
 * Blowfish.js from Dojo Toolkit 1.8.1
 * Cut of by Sladex (xslade@gmail.com)
 * 
 * Usage:
 * blowfish.encrypt(String 'subj to encrypt', String 'key', Object {outputType: 1, cipherMode: 0});
 * 
 */


(function(global){

var crypto = {};



/* dojo-release-1.8.1/dojox/encoding/crypto/_base.js.uncompressed.js */

crypto.cipherModes = {
    // summary:
    //      Enumeration for various cipher modes.
    ECB:0, CBC:1, PCBC:2, CFB:3, OFB:4, CTR:5
};
crypto.outputTypes = {
    // summary:
    //      Enumeration for input and output encodings.
    Base64:0, Hex:1, String:2, Raw:3
};



/* dojo-release-1.8.1/dojox/encoding/base64.js.uncompressed.js */

var base64 = {};
var p="=";
var tab="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

base64.encode=function(/* byte[] */ba){
    // summary:
    //      Encode an array of bytes as a base64-encoded string
    var s=[], l=ba.length;
    var rm=l%3;
    var x=l-rm;
    for (var i=0; i<x;){
        var t=ba[i++]<<16|ba[i++]<<8|ba[i++];
        s.push(tab.charAt((t>>>18)&0x3f));
        s.push(tab.charAt((t>>>12)&0x3f));
        s.push(tab.charAt((t>>>6)&0x3f));
        s.push(tab.charAt(t&0x3f));
    }
    //  deal with trailers, based on patch from Peter Wood.
    switch(rm){
        case 2:{
            var t=ba[i++]<<16|ba[i++]<<8;
            s.push(tab.charAt((t>>>18)&0x3f));
            s.push(tab.charAt((t>>>12)&0x3f));
            s.push(tab.charAt((t>>>6)&0x3f));
            s.push(p);
            break;
        }
        case 1:{
            var t=ba[i++]<<16;
            s.push(tab.charAt((t>>>18)&0x3f));
            s.push(tab.charAt((t>>>12)&0x3f));
            s.push(p);
            s.push(p);
            break;
        }
    }
    return s.join("");  //  string
};

base64.decode=function(/* string */str){
    // summary:
    //      Convert a base64-encoded string to an array of bytes
    var s=str.split(""), out=[];
    var l=s.length;
    while(s[--l]==p){ } //  strip off trailing padding
    for (var i=0; i<l;){
        var t=tab.indexOf(s[i++])<<18;
        if(i<=l){ t|=tab.indexOf(s[i++])<<12 };
        if(i<=l){ t|=tab.indexOf(s[i++])<<6 };
        if(i<=l){ t|=tab.indexOf(s[i++]) };
        out.push((t>>>16)&0xff);
        out.push((t>>>8)&0xff);
        out.push(t&0xff);
    }
    //  strip off any null bytes
    while(out[out.length-1]==0){ out.pop(); }
    return out; //  byte[]
};



/* dojo-release-1.8.1/dojo/_base/lang.js.uncompressed.js */

var lang = {};
lang.isString = function(it){
    // summary:
    //      Return true if it is a String
    // it: anything
    //      Item to test.
    return (typeof it == "string" || it instanceof String); // Boolean
};



/* dojo-release-1.8.1/dojo/_base/array.js.uncompressed.js */

var arrayUtil = {};
arrayUtil.map = function(arr, callback, thisObject, Ctr){
    // summary:
    //      applies callback to each element of arr and returns
    //      an Array with the results
    // arr: Array|String
    //      the array to iterate on. If a string, operates on
    //      individual characters.
    // callback: Function|String
    //      a function is invoked with three arguments, (item, index,
    //      array),  and returns a value
    // thisObject: Object?
    //      may be used to scope the call to callback
    // returns: Array
    // description:
    //      This function corresponds to the JavaScript 1.6 Array.map() method, with one difference: when
    //      run over sparse arrays, this implementation passes the "holes" in the sparse array to
    //      the callback function with a value of undefined. JavaScript 1.6's map skips the holes in the sparse array.
    //      For more details, see:
    //      https://developer.mozilla.org/en/Core_JavaScript_1.5_Reference/Objects/Array/map
    // example:
    //  | // returns [2, 3, 4, 5]
    //  | array.map([1, 2, 3, 4], function(item){ return item+1 });

    // TODO: why do we have a non-standard signature here? do we need "Ctr"?
    var i = 0, l = arr && arr.length || 0, out = new (Ctr || Array)(l);
    if(l && typeof arr == "string") arr = arr.split("");
    if(typeof callback == "string") callback = cache[callback] || buildFn(callback);
    if(thisObject){
        for(; i < l; ++i){
            out[i] = callback.call(thisObject, arr[i], i, arr);
        }
    }else{
        for(; i < l; ++i){
            out[i] = callback(arr[i], i, arr);
        }
    }
    return out; // Array
};



/* dojo-release-1.8.1/dojox/encoding/crypto/Blowfish.js.uncompressed.js */

/*  Blowfish
 *  Created based on the C# implementation by Marcus Hahn (http://www.hotpixel.net/)
 *  Unsigned math based on Paul Johnstone and Peter Wood patches.
 *  2005-12-08
 */
crypto.Blowfish = new function(){
    // summary:
    //      Object for doing Blowfish encryption/decryption.
    var POW2=Math.pow(2,2);
    var POW3=Math.pow(2,3);
    var POW4=Math.pow(2,4);
    var POW8=Math.pow(2,8);
    var POW16=Math.pow(2,16);
    var POW24=Math.pow(2,24);
    var iv=null;    //  CBC mode initialization vector
    var boxes={
        p:[
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
            0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
            0x9216d5d9, 0x8979fb1b
        ],
        s0:[330620164, 2060822103, 3513065911, 2997880343, 1440761582, 1635540935, 926528056, 4086129421, 51847986, 769920445, 2218953531, 2881816119, 2512973505, 2979692420, 1196448196, 2583362153, 449562910, 4086384430, 3131623109, 811125729, 2305167398, 2556948357, 338541947, 3917246838, 1157157312, 185728531, 42088913, 3484314779, 3575629800, 2818287834, 2723660448, 131216178, 3321118288, 3815036983, 1341806710, 2640193031, 500906150, 1688922406, 1156547917, 4216829348, 421184337, 2347528185, 3880382840, 4130175457, 977625670, 4980050, 1680002242, 1477944684, 3294244468, 1690487813, 159319469, 2254901093, 2334532342, 1166010456, 2727817052, 3037714640, 2658255891, 559305174, 3731864489, 3881669776, 1428374263, 616712394, 2320755099, 3217983055, 4084781236, 112187945, 1588379477, 26570142, 3876189186, 1394246566, 2977105212, 1598693196, 2372021510, 542932805, 1648303635, 217904082, 92612370, 80561350, 47213672, 1202969459, 2594480728, 4246037978, 146054816, 4063809158, 4111385100, 2895306251, 3229430945, 147124000, 540574602, 766748913, 1589329651, 2467019057, 1047968929, 2336045098, 2094346241, 2598250212, 2296244259, 3004126281, 4253247209, 1014024424, 361351297, 2162000859, 1017303821, 219304470, 2505091615, 1377116216, 633345673, 2047681453, 566169295, 2030887146, 2745957188, 4043963436, 3724475317, 1764588542, 2852667230, 591261614, 688479374, 2699877761, 3821552727, 3044501336, 3146539594, 3772590152, 3390970423, 1523507550, 4082485638, 589726651, 4117570237, 833015242, 1699125604, 2355994207, 3714339439, 359651102, 2002969084, 1761902213, 1951920170, 963483809, 3077087850, 167775322, 2561437610, 1803064313, 1396043354, 564635756, 653840701, 4004190345, 4261423787, 377337966, 1732828858, 3532619725, 926806695, 2280465132, 936519296, 1731527865, 3856151806, 174735953, 772519733, 982398973, 3441797275, 4289911183, 3423018150, 3857773004, 1859696162, 312091485, 2412389135, 2931187343, 1845601987, 4037294839, 2078580426, 3499661270, 2917577922, 1450211065, 2847025232, 471861881, 3428942862, 2513541057, 4147761690, 1368371407, 3543607760, 1446578087, 4253044190, 2016015264, 1771491556, 1306561022, 301860965, 1237903412, 3436635087, 1122849992, 43942403, 1801208019, 2873837741, 3047519931, 4169782149, 935345576, 2681024588, 544741376, 3217444418, 1982444272, 6532230, 3080005879, 1955189167, 1144642064, 1885020330, 997363968, 2244494791, 1032305162, 1825002655, 1803164961, 2510387528, 2923786622, 3762807598, 705283636, 3047912338, 2272574812, 2679595688, 2406166020, 1063388385, 1843706373, 1429964295, 2476186271, 1197557059, 923054214, 2078496334, 303285728, 2452319114, 3546653038, 1861040591, 2503505935, 2682600779, 1938223198, 3397355733, 166189620, 1060839095, 2791799162, 3599176666, 2458127763, 4270496763, 3356693377, 2686309738, 718899852, 1511329684, 188371255, 1320545909, 3562436838, 2868304078, 564279692, 3207175878, 3118535785, 1412387975, 1596149191, 2993030400, 1951723606, 3223631615, 4270926768, 510854762, 2775103807, 1350992990, 3856192164],
        s1:[2134083986, 2294672761, 1568630117, 1213751332, 2049258132, 1335413291, 214218624, 206302044, 455891899, 2600300503, 3037664070, 3874154714, 2939942619, 1479808258, 790817859, 3283507579, 494784429, 327941988, 1466957733, 4028685177, 1484151855, 2274265581, 3443739464, 1101484572, 1582447336, 537242257, 3321757787, 1110961315, 141760430, 3420443595, 2481363872, 1199041156, 2752168798, 1849172845, 1404780074, 4167588135, 1181993666, 4046158640, 2562105, 3752189915, 1638585789, 3443060796, 4090793371, 389965244, 640477054, 2912211400, 2933422310, 1108230129, 3678880880, 2863224196, 2312952183, 2368883840, 1118741068, 1071366043, 3158635558, 1812351432, 3656524696, 609589144, 73312591, 2028951918, 2640398216, 3415375751, 3883124874, 3070273131, 3345804080, 772458317, 1834397813, 1413656741, 3015713435, 1632164623, 4276783227, 2471613270, 80450617, 510221145, 3369936247, 3132692803, 3764572649, 1541572194, 3968948457, 1263637926, 3673740453, 3258343868, 2334876939, 3718180190, 161137571, 2767773545, 1950680617, 2417155817, 2143338136, 3916829252, 718679849, 4275375960, 919890304, 754333507, 2725557545, 1266320200, 922261819, 343493664, 185243350, 3102582978, 3030084087, 3196948372, 2413140452, 261415577, 2047391563, 3720166197, 54633967, 3633000375, 4193841053, 96106954, 204415435, 1099784104, 3976838223, 1466458561, 1136874261, 1410141523, 2176126436, 2559227438, 2195760306, 3920590287, 2470625327, 2546846871, 1897424294, 2704144105, 2077941605, 1971636626, 649364866, 3716537042, 2833604010, 1214863635, 1968471928, 2601905715, 209122716, 1483583242, 1850834401, 3590655150, 862620419, 4250362298, 1056345829, 3595808421, 2897306314, 4126714649, 2070256047, 3028183274, 905649663, 3594731825, 3067243369, 480829643, 3788470672, 279169375, 4285610003, 433501364, 1173637676, 3095578910, 3061021696, 2730401904, 2343648902, 686536377, 4227542437, 1130352362, 41590801, 1239190075, 3271413546, 913000197, 2703631346, 868297870, 1520232696, 3731099650, 3285157098, 2270604474, 343737676, 2466543282, 338279824, 3404931789, 2018076593, 1382397820, 2549292328, 3340822770, 1047406579, 3257344017, 1677368603, 3541406442, 720138768, 3768871279, 2229431524, 2425282293, 2212715087, 989529761, 1036487200, 2788995838, 3913117344, 2963522688, 3263700007, 2949970098, 3753976320, 1324354690, 778497392, 1503394804, 1570238111, 2999761242, 1818117835, 2668412640, 1661711652, 983987754, 1854161991, 3121182586, 1916988765, 326576799, 140993384, 836524239, 2135082585, 3800038976, 1716519964, 1409898551, 3818216391, 3441763839, 4144644274, 651214367, 2005779267, 1010597585, 2224838354, 2281099429, 3959397623, 2579226373, 3190603611, 1314710785, 857774299, 447984065, 2905388739, 3112888481, 2800365196, 1765166560, 3817725287, 1950555023, 1246532011, 3516225341, 1706062606, 1174195102, 2066985033, 1513168718, 3766047659, 819223181, 171767018, 486139292, 2680668716, 3028345660, 2662604625, 3411320474, 2137060353, 2640869555, 4183921695, 1362143769, 3927563211, 2533353406, 2738490655, 664715603],
        s2:[3086201715, 2586741608, 574263525, 3476232056, 2223477154, 225885113, 3623901477, 2990838870, 152173715, 574224293, 1493177362, 1892466566, 2652463036, 140700690, 3785208768, 1923275378, 4170842844, 243609233, 1317135715, 1818972963, 4181456537, 3577558081, 4112451866, 764719810, 1025782221, 1568153109, 945370529, 340509802, 3230657335, 2568517000, 3654407744, 526168242, 4181394015, 4046714007, 2456097260, 1955425600, 1434525941, 4243403174, 1980628355, 150259294, 96272650, 1926351037, 1177259191, 3530950251, 2809799182, 759265885, 3642735652, 3398245592, 1452791945, 3900473082, 1522896840, 3171998228, 1232582173, 492965095, 256443118, 3384984484, 437243972, 1327168355, 295175512, 838705536, 2155636248, 3160020279, 930437719, 3938973311, 730012694, 1443402776, 989458237, 676400753, 675928778, 2861498592, 3947050852, 4173361778, 373825784, 507740021, 665299164, 2950301322, 676363199, 3250349566, 3869997703, 3893901781, 3712451300, 3357194204, 3068100194, 1799434711, 4261521506, 2110651801, 2723716939, 1336990672, 1670567173, 1229633256, 1686213532, 1326610780, 3036198337, 1375167360, 1990913945, 876621230, 824071724, 3629127290, 2241439364, 4238650993, 1555595869, 2065438628, 2065421071, 460011033, 579279164, 375460866, 712861562, 747408733, 4264392468, 4201719185, 1803564228, 175816242, 1134539538, 3798768406, 1665897173, 824770199, 2971493403, 3911221414, 1283694479, 164359480, 137976892, 2218420562, 279313758, 2342079929, 1718915258, 1616774207, 3027480257, 2039873101, 3164684188, 3197543203, 1930459644, 1077337629, 2988385875, 3378239247, 609032205, 1267993240, 4055921642, 339862300, 1733707954, 2021962203, 3154040072, 1612231033, 3351736095, 451645172, 1710357439, 1731052556, 4044663780, 3192444323, 826373393, 1695961270, 3150744369, 3579068694, 3123243195, 3394082065, 3158562444, 4115967954, 155721414, 1218005573, 3452785096, 2123793111, 453738261, 1512815734, 3264768750, 4048608473, 2314671356, 67312111, 1560633462, 1341162286, 3123720625, 2300385581, 1344037919, 2024479970, 3812138571, 1989418638, 4169854054, 1845631027, 3703623589, 1054248791, 1131362678, 479245172, 2603464837, 2276533877, 4009425202, 176350783, 88761070, 3722679357, 1119525588, 1302481288, 2170181258, 2510469687, 171362380, 2816700434, 2174335953, 743606726, 1984841601, 3288809077, 436321101, 2121685076, 1519404847, 567371210, 2030086981, 3401013613, 94303266, 671558092, 3715906013, 1704694805, 3077699369, 2755801626, 2138739827, 3161110610, 2417838093, 2892827908, 3026223082, 393525446, 2626069132, 3466126112, 1068687950, 1556224010, 1901105971, 713393597, 3287109647, 3574958115, 2399208638, 3711300085, 3756767970, 3687203943, 2671304301, 276830235, 2031511572, 485831, 1419657858, 2626326499, 1785853694, 783637862, 2700510211, 884513671, 2521110022, 4157672725, 2996699533, 2661535483, 1361668714, 611497768, 3765213655, 2284540662, 2814563039, 1288608747, 2884076645, 400138379, 8657886, 853011629, 2505433752, 1531207334, 1568471363, 932967245, 2234597937, 1731642059],
        s3:[888795298, 1065829853, 355680023, 3035612930, 3384184234, 4305883, 418902792, 1406611678, 2650291588, 2447924778, 1445260450, 244792890, 1927463954, 3942920424, 1638604299, 2591534867, 368979641, 3262957037, 429259565, 2796324314, 4275821080, 3985807513, 1620561015, 1828439068, 2657293809, 2160073063, 629350328, 921975942, 4132667470, 1326784119, 3949061507, 365899970, 4179642299, 2525490983, 2413215073, 3586557116, 3846309681, 779610757, 4165770712, 8706926, 2764310574, 2305928521, 589164575, 2519131743, 264974123, 2298302915, 3250844958, 4111004306, 3043291271, 4196744180, 2162100786, 442991502, 2415416242, 1730457576, 3335933934, 1453763837, 4015834438, 2776253474, 2337203428, 1274185998, 2723839604, 1718482366, 3169370959, 3466140591, 693621011, 3369111732, 1932598587, 594123894, 2827595334, 3501383308, 4188718247, 3607957714, 4159727006, 1600964211, 2054959827, 878101250, 523334239, 557810845, 106976718, 804855566, 1108281673, 2778575249, 1474504724, 2068716732, 3309158449, 3168786892, 2417559519, 490033522, 1810671725, 3727097852, 110708647, 3560930959, 3277703409, 1337873376, 3898774269, 1373712835, 829549236, 1682908828, 1796425183, 510197135, 2602780120, 887352364, 3955937093, 3557323010, 2306772695, 2929588840, 949089700, 240972688, 1736939438, 4256588746, 592811715, 1682325141, 1348506347, 3510977810, 502359592, 1579232261, 2878984261, 33256849, 2328286510, 1473858686, 2409863961, 3455091141, 1042494602, 3646582220, 3890845991, 3058274228, 1501295092, 4019664044, 3491562372, 3563363402, 2605678681, 2822279296, 3437602200, 1324963257, 4083053530, 3636245849, 3790838241, 1449559740, 4272222878, 3887531671, 3496362192, 4165014620, 3745751637, 1537291056, 504957967, 3052404903, 2911491588, 2205060970, 2839559993, 3573418141, 2227609749, 2398781624, 732476368, 4221373266, 279726694, 153459485, 4120150820, 2390638122, 816010975, 2805329503, 3658757774, 136321217, 793391077, 4094209553, 1014554441, 1567261190, 3140962517, 1563709501, 3243142885, 1025626800, 3251069038, 3493652594, 892287035, 3687168807, 3853077231, 110787196, 3546389367, 2717600947, 1435142510, 1029084972, 4146023347, 514051472, 1445379655, 243767839, 423286364, 694032483, 3637427255, 3641346917, 3010558826, 473297214, 53212073, 4118376112, 2043575882, 3150808398, 3018956129, 3039411054, 906606862, 1382428413, 1860821141, 468278813, 1019616616, 665731121, 1334968403, 3722673880, 1533182875, 1698599195, 593915845, 618604014, 3886228089, 1231956686, 3331874007, 1392345921, 1453824829, 971069355, 2263694198, 3299578551, 2768864749, 890383483, 1260353899, 2173332769, 2400588455, 3757066458, 3692327344, 1672261252, 1975403561, 642418522, 2363650023, 913034930, 2494032270, 1808797364, 1417767766, 115173825, 4171723553, 3170430189, 936503735, 2965635818, 1974235361, 2787204717, 2270577874, 2074132209, 2666029106, 3420884363, 2415942865, 1883458107, 2800370929, 1351509016, 3421607379, 3526820437, 3121555188, 4096326929, 3290806866, 16591512, 1435022798, 2044251026, 1805597046, 3286882916]
    }
////////////////////////////////////////////////////////////////////////////
//  fixes based on patch submitted by Peter Wood (#5791)
    function add(x,y){
        return (((x>>0x10)+(y>>0x10)+(((x&0xffff)+(y&0xffff))>>0x10))<<0x10)|(((x&0xffff)+(y&0xffff))&0xffff);
    }
    function xor(x,y){
        return (((x>>0x10)^(y>>0x10))<<0x10)|(((x&0xffff)^(y&0xffff))&0xffff);
    }

    function $(v, box){
        var d=box.s3[v&0xff]; v>>=8;
        var c=box.s2[v&0xff]; v>>=8;
        var b=box.s1[v&0xff]; v>>=8;
        var a=box.s0[v&0xff];

        var r = (((a>>0x10)+(b>>0x10)+(((a&0xffff)+(b&0xffff))>>0x10))<<0x10)|(((a&0xffff)+(b&0xffff))&0xffff);
        r = (((r>>0x10)^(c>>0x10))<<0x10)|(((r&0xffff)^(c&0xffff))&0xffff);
        return (((r>>0x10)+(d>>0x10)+(((r&0xffff)+(d&0xffff))>>0x10))<<0x10)|(((r&0xffff)+(d&0xffff))&0xffff);
    }
////////////////////////////////////////////////////////////////////////////
    function eb(o, box){
        //  TODO: see if this can't be made more efficient
        var l=o.left;
        var r=o.right;
        l=xor(l,box.p[0]);
        r=xor(r,xor($(l,box),box.p[1]));
        l=xor(l,xor($(r,box),box.p[2]));
        r=xor(r,xor($(l,box),box.p[3]));
        l=xor(l,xor($(r,box),box.p[4]));
        r=xor(r,xor($(l,box),box.p[5]));
        l=xor(l,xor($(r,box),box.p[6]));
        r=xor(r,xor($(l,box),box.p[7]));
        l=xor(l,xor($(r,box),box.p[8]));
        r=xor(r,xor($(l,box),box.p[9]));
        l=xor(l,xor($(r,box),box.p[10]));
        r=xor(r,xor($(l,box),box.p[11]));
        l=xor(l,xor($(r,box),box.p[12]));
        r=xor(r,xor($(l,box),box.p[13]));
        l=xor(l,xor($(r,box),box.p[14]));
        r=xor(r,xor($(l,box),box.p[15]));
        l=xor(l,xor($(r,box),box.p[16]));
        o.right=l;
        o.left=xor(r,box.p[17]);
    }

    function db(o, box){
        var l=o.left;
        var r=o.right;
        l=xor(l,box.p[17]);
        r=xor(r,xor($(l,box),box.p[16]));
        l=xor(l,xor($(r,box),box.p[15]));
        r=xor(r,xor($(l,box),box.p[14]));
        l=xor(l,xor($(r,box),box.p[13]));
        r=xor(r,xor($(l,box),box.p[12]));
        l=xor(l,xor($(r,box),box.p[11]));
        r=xor(r,xor($(l,box),box.p[10]));
        l=xor(l,xor($(r,box),box.p[9]));
        r=xor(r,xor($(l,box),box.p[8]));
        l=xor(l,xor($(r,box),box.p[7]));
        r=xor(r,xor($(l,box),box.p[6]));
        l=xor(l,xor($(r,box),box.p[5]));
        r=xor(r,xor($(l,box),box.p[4]));
        l=xor(l,xor($(r,box),box.p[3]));
        r=xor(r,xor($(l,box),box.p[2]));
        l=xor(l,xor($(r,box),box.p[1]));
        o.right=l;
        o.left=xor(r,box.p[0]);
    }

    //  Note that we aren't caching contexts here; it might take a little longer
    //  but we should be more secure this way.
    function init(key){
        var k=key;
        if(lang.isString(k)){
            k = arrayUtil.map(k.split(""), function(item){
                return item.charCodeAt(0) & 0xff;
            });
        }

        //  init the boxes
        var pos=0, data=0, res={ left:0, right:0 }, i, j, l;
        var box = {
            p: arrayUtil.map(boxes.p.slice(0), function(item){
                var l=k.length, j;
                for(j=0; j<4; j++){ data=(data*POW8)|k[pos++ % l]; }
                return (((item>>0x10)^(data>>0x10))<<0x10)|(((item&0xffff)^(data&0xffff))&0xffff);
            }),
            s0:boxes.s0.slice(0),
            s1:boxes.s1.slice(0),
            s2:boxes.s2.slice(0),
            s3:boxes.s3.slice(0)
        };

        //  encrypt p and the s boxes
        for(i=0, l=box.p.length; i<l;){
            eb(res, box);
            box.p[i++]=res.left, box.p[i++]=res.right;
        }
        for(i=0; i<4; i++){
            for(j=0, l=box["s"+i].length; j<l;){
                eb(res, box);
                box["s"+i][j++]=res.left, box["s"+i][j++]=res.right;
            }
        }
        return box;
    }

////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////
    this.getIV=function(/* dojox.encoding.crypto.outputTypes? */ outputType){
        // summary:
        //      returns the initialization vector in the output format specified by outputType
        var out=outputType||crypto.outputTypes.Base64;
        switch(out){
            case crypto.outputTypes.Hex:{
                return arrayUtil.map(iv, function(item){
                    return (item<=0xf?'0':'')+item.toString(16);
                }).join("");            //  string
            }
            case crypto.outputTypes.String:{
                return iv.join("");     //  string
            }
            case crypto.outputTypes.Raw:{
                return iv;              //  array
            }
            default:{
                return base64.encode(iv);   //   string
            }
        }
    };

    this.setIV=function(/* string */data, /* dojox.encoding.crypto.outputTypes? */inputType){
        // summary:
        //      sets the initialization vector to data (as interpreted as inputType)
        var ip=inputType||crypto.outputTypes.Base64;
        var ba=null;
        switch(ip){
            case crypto.outputTypes.String:{
                ba = arrayUtil.map(data.split(""), function(item){
                    return item.charCodeAt(0);
                });
                break;
            }
            case crypto.outputTypes.Hex:{
                ba=[];
                for(var i=0, l=data.length-1; i<l; i+=2){
                    ba.push(parseInt(data.substr(i,2), 16));
                }
                break;
            }
            case crypto.outputTypes.Raw:{
                ba=data;
                break;
            }
            default:{
                ba=base64.decode(data);
                break;
            }
        }
        //  make it a pair of words now
        iv={};
        iv.left=ba[0]*POW24|ba[1]*POW16|ba[2]*POW8|ba[3];
        iv.right=ba[4]*POW24|ba[5]*POW16|ba[6]*POW8|ba[7];
    };

    this.encrypt = function(/* string */plaintext, /* string */key, /* object? */ao){
        // summary:
        //      encrypts plaintext using key; allows user to specify output type and cipher mode via keyword object "ao"
        var out=crypto.outputTypes.Base64;
        var mode=crypto.cipherModes.ECB;
        if (ao){
            if (ao.outputType) out=ao.outputType;
            if (ao.cipherMode) mode=ao.cipherMode;
        }

        var bx = init(key), padding = 8-(plaintext.length&7);
        for (var i=0; i<padding; i++){ plaintext+=String.fromCharCode(padding); }

        var cipher=[], count=plaintext.length >> 3, pos=0, o={}, isCBC=(mode==crypto.cipherModes.CBC);
        var vector={left:iv.left||null, right:iv.right||null};
        for(var i=0; i<count; i++){
            o.left=plaintext.charCodeAt(pos)*POW24
                |plaintext.charCodeAt(pos+1)*POW16
                |plaintext.charCodeAt(pos+2)*POW8
                |plaintext.charCodeAt(pos+3);
            o.right=plaintext.charCodeAt(pos+4)*POW24
                |plaintext.charCodeAt(pos+5)*POW16
                |plaintext.charCodeAt(pos+6)*POW8
                |plaintext.charCodeAt(pos+7);

            if(isCBC){
                o.left=(((o.left>>0x10)^(vector.left>>0x10))<<0x10)|(((o.left&0xffff)^(vector.left&0xffff))&0xffff);
                o.right=(((o.right>>0x10)^(vector.right>>0x10))<<0x10)|(((o.right&0xffff)^(vector.right&0xffff))&0xffff);
            }

            eb(o, bx);  //  encrypt the block

            if(isCBC){
                vector.left=o.left;
                vector.right=o.right;
            }

            cipher.push((o.left>>24)&0xff);
            cipher.push((o.left>>16)&0xff);
            cipher.push((o.left>>8)&0xff);
            cipher.push(o.left&0xff);
            cipher.push((o.right>>24)&0xff);
            cipher.push((o.right>>16)&0xff);
            cipher.push((o.right>>8)&0xff);
            cipher.push(o.right&0xff);
            pos+=8;
        }

        switch(out){
            case crypto.outputTypes.Hex:{
                return arrayUtil.map(cipher, function(item){
                    return (item<=0xf?'0':'')+item.toString(16);
                }).join("");    //  string
            }
            case crypto.outputTypes.String:{
                return cipher.join(""); //  string
            }
            case crypto.outputTypes.Raw:{
                return cipher;  //  array
            }
            default:{
                return base64.encode(cipher);   //  string
            }
        }
    };

    this.decrypt = function(/* string */ciphertext, /* string */key, /* object? */ao){
        // summary:
        //      decrypts ciphertext using key; allows specification of how ciphertext is encoded via ao.
        var ip=crypto.outputTypes.Base64;
        var mode=crypto.cipherModes.ECB;
        if (ao){
            if (ao.outputType) ip=ao.outputType;
            if (ao.cipherMode) mode=ao.cipherMode;
        }
        var bx = init(key);
        var pt=[];

        var c=null;
        switch(ip){
            case crypto.outputTypes.Hex:{
                c = [];
                for(var i=0, l=ciphertext.length-1; i<l; i+=2){
                    c.push(parseInt(ciphertext.substr(i,2), 16));
                }
                break;
            }
            case crypto.outputTypes.String:{
                c = arrayUtil.map(ciphertext.split(""), function(item){
                    return item.charCodeAt(0);
                });
                break;
            }
            case crypto.outputTypes.Raw:{
                c=ciphertext;   //  should be a byte array
                break;
            }
            default:{
                c=base64.decode(ciphertext);
                break;
            }
        }

        var count=c.length >> 3, pos=0, o={}, isCBC=(mode==crypto.cipherModes.CBC);
        var vector={left:iv.left||null, right:iv.right||null};
        for(var i=0; i<count; i++){
            o.left=c[pos]*POW24|c[pos+1]*POW16|c[pos+2]*POW8|c[pos+3];
            o.right=c[pos+4]*POW24|c[pos+5]*POW16|c[pos+6]*POW8|c[pos+7];

            if(isCBC){
                var left=o.left;
                var right=o.right;
            }

            eb(o, bx);  //  decrypt the block

            if(isCBC){
                o.left=(((o.left>>0x10)^(vector.left>>0x10))<<0x10)|(((o.left&0xffff)^(vector.left&0xffff))&0xffff);
                o.right=(((o.right>>0x10)^(vector.right>>0x10))<<0x10)|(((o.right&0xffff)^(vector.right&0xffff))&0xffff);
                vector.left=left;
                vector.right=right;
            }

            pt.push((o.left>>24)&0xff);
            pt.push((o.left>>16)&0xff);
            pt.push((o.left>>8)&0xff);
            pt.push(o.left&0xff);
            pt.push((o.right>>24)&0xff);
            pt.push((o.right>>16)&0xff);
            pt.push((o.right>>8)&0xff);
            pt.push(o.right&0xff);
            pos+=8;
        }

        //  check for padding, and remove.
        if(pt[pt.length-1]==pt[pt.length-2]||pt[pt.length-1]==0x01){
            var n=pt[pt.length-1];
            pt.splice(pt.length-n, n);
        }
        //console.log(pt)
        //  convert to string
        return arrayUtil.map(pt, function(item){
            return (item<=0xf?'0':'')+item.toString(16);
        }).join("");    //  string
    };

    this.setIV("0000000000000000", crypto.outputTypes.Hex);
}();



if (typeof exports != 'undefined') {
    exports.blowfish = crypto.Blowfish;
} else {
    global.blowfish = crypto.Blowfish;
}

}(this));