

const aesjs = require('aes-js');
// the encryption encoding function.
ChunkAsBytes= "";
var newtext = "GeecksforGeecks.";
ChunkAsBytes = aesjs.utils.utf8.toBytes(newtext);
console.log(`plain as bytes: ${ChunkAsBytes}`);
const utf8Encode = new TextEncoder();
const byteArr = utf8Encode.encode(newtext);
console.log(`the encoded: ${byteArr}`);

function encrypt_encode(plain)
{       
    var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    var aes = new aesjs.AES(key);
    //console.log(textAsBytes);
    var chunk ;
    var encryptedBytes;
    var encryptedChunk;
    var Entiretext="";
    var textTosend="";
    var zeros="";
    var len="";

        for( i = 0; i < plain.length; i+=16){
            chunk = plain.slice(i, i + 16);
            if (chunk.length < 16){
                for(let i=0; i<(16-chunk.length) ; i++)
                     zeros=zeros.concat(" ");
                chunk=chunk.concat(zeros);
                //console.log(`chunk:${chunk}`);
                }
            ChunkAsBytes = aesjs.utils.utf8.toBytes(chunk);
            //console.log(ChunkAsBytes);
            encryptedBytes = aes.encrypt(ChunkAsBytes);
            encryptedChunk = Buffer.from(encryptedBytes).toString('base64');
            Entiretext = Entiretext.concat(encryptedChunk);
        }
        len= Entiretext.length.toString();
        textTosend = textTosend.concat(len, Entiretext);
        return textTosend;     
}
console.log(encrypt_encode(newtext));

function toHexString(byteArray) {
    var s = '0x';
    byteArray.forEach(function(byte) {
      s += ('0' + (byte & 0xFF).toString(16)).slice(-2);
    });
    return s;
  }

// this function is running in this context 
function decode_decrypt(cipher)
{       
    var key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    var aes = new aesjs.AES(key);
    var chunk ;
    var decryptedBytes;
    var decryptedChunk;
    var Entiretext="";

    // chunking 24 byte at a time
        for( i = 2; i < cipher.length; i+=24){
            chunk = cipher.slice(i, i + 24);
            console.log(`Chunk: ${chunk}`);
            DecChunk = Buffer.from(chunk,'base64');
            //console.log(`DecChunk: ${DecChunk}`);
            //console.log(`DecChunk_length: ${DecChunk.length}`);
            // Decryption-Decoding
            
            decryptedBytes = aes.decrypt(DecChunk);
            decryptedChunk = Buffer.from(decryptedBytes);
            Entiretext = Entiretext.concat(decryptedChunk);

        }
        return Entiretext;     
}
console.log(encrypt_encode(newtext));
console.log(decode_decrypt(encrypt_encode(newtext)));

  