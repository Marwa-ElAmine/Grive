

const aesjs = require('aes-js');
var text = "This is a message from the server. you must be able to read it correctly!!";
// the encryption encoding function.
function encrypt_encode(plain)
{       
    var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    var aes = new aesjs.AES(key);
    var chunk ;
    var ChunkAsBytes;
    var encryptedBytes;
    var Entiretext="";
    var zeros="";
    var len="";
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
        var base64tex="";
        var textTosend=""
        base64text = Buffer.from(Entiretext).toString('base64');
        len= base64text.length.toString();
        textTosend = textTosend.concat(len, base64text);
        return textTosend;     
}
console.log(encrypt_encode(text));

function decode_decrypt(plain)
{       
    var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    var aes = new aesjs.AES(key);
    var chunk ;
    var DecChunk;
    var ChunkAsBytes;
    var encryptedBytes;
    var Entiretext="";
    var zeros="";
    var len="";
        for( i = 2; i < plain.length; i+=24){
            chunk = plain.slice(i, i + 24);
            DecChunk = Buffer.from(chunk).toString('utf8');
            console.log(DecChunk);
            // if (chunk.length < 16){
            //     for(let i=0; i<(16-chunk.length) ; i++)
            //          zeros=zeros.concat("0");
            //     chunk=chunk.concat(zeros);
            //     }
            
            ChunkAsBytes = aesjs.utils.utf8.toBytes(chunk);
            decryptedBytes = aes.decrypt(ChunkAsBytes);
            Entiretext = Entiretext.concat(encryptedBytes)
            console.log(encryptedBytes);

        }
        var textTosend=""
        base64text = Buffer.from(Entiretext).toString('utf8');
        len= base64text.length.toString();
        textTosend = textTosend.concat(len, base64text);
        return textTosend;     
}
console.log(encrypt_encode(text));
console.log(decode_decrypt(encrypt_encode(text)));
  