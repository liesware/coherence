var net = require('net');

var crypto = require("crypto");
function randomhex (num) {
	//var num = Math.floor(Math.random() * (high - low + 1) + low);
	var id = crypto.randomBytes(num).toString('hex');
    return id;
}

function cohererence_client(jsonContent){
  //var jsonContent = JSON.parse(ajson);
  var answ;
  //jsonContent.payload='abc'.repeat(20);

  var client = new net.Socket();
  client.connect(6613, '127.0.0.1', function() {
	console.log('Connected: '+ JSON.stringify(jsonContent)+'\n');
	client.write(JSON.stringify(jsonContent));
  });

  client.on('data', function(data) {
	console.log('Received: ' + data+'\n');
	answ = JSON.parse(data);
//	console.log( jsonContent.hash);
//	test="{"+randomIntInc(1,200)+"}";
//	test=randomIntInc(1,200);
	client.destroy(); 
  });

  client.on('close', function() {
	console.log('Connection closed');
	return answ;
  });
  
  
}

//*


function cohererence_json(algo, fam ,ajson){
for (k in fam)
for (i in algo) {
  for(j in ajson){
    var jsonContent = JSON.parse(ajson[j]);	
    jsonContent.family=fam[k];
    jsonContent.algorithm=algo[i];
    cohererence_client(jsonContent);
  }    
} 

}

var mac_poly = ['POLY1305']
var mac_hmac = ['HMAC']
var mac_cvmac= ['CMAC','VMAC' ]



var fam_hash=['sha3_512','sha3_384','sha3_256','sha3_224',
'sha_512','sha_384','sha_256','sha_224',
'sha_1','whirlpool']

var fam_block=['aes', 'rc6', 'mars','serpent','twofish', 'cast256','camellia']


var mac_json=[
'{ "version": 1 , "algorithm":"POLY1305" , "type":"string", "plaintext": "616263", "hex": 1,\
"key":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF","iv":"0123456789ABCDEF0123456789ABCDEF", \
"nonce":"0123456789ABCDEF0123456789ABCDEF"}',
'{ "version": 1 , "algorithm":"POLY1305" , "type":"string", "plaintext": "abc", "hex": 0,\
"key":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF","iv":"0123456789ABCDEF0123456789ABCDEF", \
"nonce":"0123456789ABCDEF0123456789ABCDEF"}',
'{ "version": 1 , "algorithm":"POLY1305" , "type":"string", "plaintext": "abc",\
"key":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF","iv":"0123456789ABCDEF0123456789ABCDEF", \
"nonce":"0123456789ABCDEF0123456789ABCDEF"}',
'{ "version": 1 , "algorithm":"POLY1305" , "type":"file", "file": "file_test/AB.mayhem",\
"key":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "iv":"0123456789ABCDEF0123456789ABCDEF",\
"nonce":"0123456789ABCDEF0123456789ABCDEF"}',

];


for(j in mac_json){
    var jsonContent = JSON.parse(mac_json[j]);	
    cohererence_client(jsonContent);
}  

cohererence_json(mac_hmac,fam_hash,mac_json)
cohererence_json(mac_cvmac,fam_block,mac_json)
