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


var rand_al = [ 'RAND_RP', 'RAND_AUTO'];

var rand_json=[
'{ "version": 1 , "algorithm":"RAND_RP" , "length": 12}',
'{ "version": 1 , "algorithm":"RAND_RP" , "length": 12 , "entropy":0}',
'{ "version": 1 , "algorithm":"RAND_RP" , "length": 12 , "entropy":1}',
'{ "version": 1 , "algorithm":"RAND_RP" , "length": 12 , "entropy":2}'
];	

cohererence_json(rand_al, rand_json);

test_val='{"version":1,"algorithm":"RAND_RDRAND","length":12,"entropy":2}'
cohererence_client(JSON.parse(test_val))
