How to operate my application:

First, run it with parameters for file names where you will store encoded key pairs. Use "-g" for the mode to generate
	these initial key pairs.

	Example: -g pub1.class priv1.class pub2.class priv2.class
	
	You can name your files something else, but you must use them correctly in the subsequent program executions.


Then, create a text document in the same directory. Write the message you want to be encoded. For example, use:

	pt.txt
	
	You can name your files something else, but you must use them correctly in the subsequent program executions.


Then, run the application in encryption mode with "-e" and parameters for the destination's public key (for encryption), 
	the sender's private key (for signing), the input file to be encrypted, and the output file where the ciphertext 
	will be written.

	Example: -e pub1.class priv2.class pt.txt ct.class

	You can name ct.class something else is you want, but you must use that name in subsequent calls. You must also
	use the same key and plaintext file names that you used before.


Then, run the application in decryption mode with "-d" and parameters for the destination's private key (for decryption),
	the sender's public key (for verification), the encrypted ciphertext to be decrypted, and the output file where 
	the decrypted ciphertext (plaintext) will be written.

	Example: -d pub2.class priv1.class ct.class decoded.txt

	You can name the output file whatever you want, but the other parameters must match what you have used and 
	generated previously


Finally, open "pt.txt" and "decoded.txt" to check that the messages match.