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


function cohererence_json(algo ,ajson){

for (i in algo) {
  for(j in ajson){
    var jsonContent = JSON.parse(ajson[j]);	
    jsonContent.algorithm=algo[i];
    cohererence_client(jsonContent);
  }    
} 

}


var hash_al = [ 'SHA3_512', 'SHA3_384', 'SHA3_256', 'SHA3_224',
'SHA_512', 'SHA_384', 'SHA_256', 'SHA_224' , 'SHA_1' ,
'WHIRLPOOL' , 'BLAKE2B'];

var hash_json=[
'{ "version": 1 , "algorithm":"SHA3_512" , "type":"string", "plaintext": "616263", "hex": 1}',
'{ "version": 1 , "algorithm":"SHA3_512" , "type":"string", "plaintext": "abc", "hex": 0}',
'{ "version": 1 , "algorithm":"SHA3_512" , "type":"string", "plaintext": "abc"}',
'{ "version": 1 , "algorithm":"SHA3_512" , "type":"file" , "file":"file_test/AB.mayhem"}'
];	

cohererence_json(hash_al,hash_json);
