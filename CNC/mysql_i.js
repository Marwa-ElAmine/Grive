const readline = require('node:readline');
const Mysql = require ('mysql2');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'Mysql>'
});

const con = Mysql.createConnection({
    host: "172.18.18.17",
    port: 3306,
    user: "grive",
    password: "envoletoi",
    database: "Grivedb"
});

let command = null;
let IoT = null;
rl.on('line', (line)=>{
command = line.trim();

if(command != null){
    con.query(command, (err, result)=>{
        if (err) throw err;
        console.log(result);
        if(result.length === 0) console.log('Not in the table!')
        result.forEach(element => {
            console.log(element.ID);
        });
       /* IoT = result;
        console.log(typeof result);
        console.log(Object.getOwnPropertyNames(IoT));
        console.log(IoT[0]['status']);
        command = null;*/
    });
}
});

con.connect((err)=>{
    if (err) throw err;
    console.log('Connected to Mysql server!');
})