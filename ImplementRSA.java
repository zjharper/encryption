/* ImplementRSA - CS 469 - Zachary Harper
 * 
 * In this application, we use java.math.BigInteger and java.security.SecureRandom to
 * demonstrate a java application of RSA encryption. The message is a randomly generated
 * BigInteger. It will be encrypted, decrypted and printed at each step.
 * 
 * Stipulations for this code include
 * 1: primes p and q are both 1536-bit
 * 2: The difference between p and q is greater than 2^768
 * 3: The message is coprime to the modulus N = pq
 * 4: Timing is calculated by repeating encryption and decryption 100 times
 * 5: The public key element e is set to 65537
 * 6: The java application is compilable using javac
 * 	6a: Instructions for compilation
 * 		6ai: Set JDK environment variable for use in powershell
 * 		6aii: Enter working directory of ImplementRSA.java
 * 		6aiii: Run command>> javac ImplementRSA.java
 * 	6b: Instructions for executing
 * 		6bi: enter working directory with ImplementRSA.class
 * 		6bii: Run command>> java ImplementRSA
 */

import java.math.BigInteger; //necessary for representing larger numbers than long types
import java.security.SecureRandom; //generates message, p and q

public class ImplementRSA {

	private final static BigInteger one = new BigInteger("1"); // for defining phi
	private final static BigInteger publicKey = new BigInteger("65537"); // public key component e
	private final static SecureRandom random = new SecureRandom(); // for creating p & q
	private BigInteger p, q, modulus, privateKey, diff,coprime; // instantiate variable for use within the method
	private BigInteger minDiff = new BigInteger("2"); //this number will be raised to 768 before creating p and q

	ImplementRSA(int N) { // create a 1536^2-bit private key
		minDiff = minDiff.pow(768);	// minimum difference between p and q
		do
		{
			p = BigInteger.probablePrime(N, random); // 1536-bit value
			q = BigInteger.probablePrime(N, random); // 1536-bit value
			diff = p.subtract(q).abs(); // calculate the difference between p and q
		}while(diff.compareTo(minDiff) != 1); // ensure difference is > 2^768

		BigInteger phi = (p.subtract(one)).multiply(q.subtract(one)); //create phi as (p-1)(q-1)
		modulus = p.multiply(q); //create modulus as p*q
		privateKey = publicKey.modInverse(phi); // returns publicKey^-1 mod phi
	}

	void checkCoprime(BigInteger message){ //Check that modulus and message are coprime
		coprime = modulus.modInverse(message);
		if (coprime.compareTo(one) > 0) {
			System.out.println("\nMessage and modulus are coprime!");
		} else {
			System.out.println("\nMessage and modulus are not coprime!");
		}
		return;
	}
	
	BigInteger encrypt(BigInteger message) {
		return message.modPow(publicKey, modulus); //encrypts message c = mes^pubkey(mod n)
	}

	BigInteger decrypt(BigInteger encrypted) {
		return encrypted.modPow(privateKey, modulus); //decrypts message: mes = c^privkey(mod n)
	}

	public String toString() {
		String s = "\npublic  = "+publicKey+"\n\nprivate = "+privateKey + "\n\nmodulus = "+modulus;
		return s; //format for printing public key, private key, and modulus
	}

	public static void main(String[] args) {
		int bits = 1536;  // message will be 1535-bits, p and q will be 1536-bit
		BigInteger message = new BigInteger(bits-1, random);
		ImplementRSA key = new ImplementRSA(bits);

		long start = System.currentTimeMillis(); //Start timer for encryption/decryption 100 times
		for(int x = 0; x < 99; x = x+1){
			BigInteger encrypt = key.encrypt(message);
			BigInteger decrypt = key.decrypt(encrypt);
		}
		long end = System.currentTimeMillis(); //Stop timer
		long elapse = (end - start) / 100; //Calculate average time of each enc/dec in ms
		System.out.println("\nElapsed = " + elapse + "ms per encrypt + decrypt"); //Print avg time
		
		key.checkCoprime(message);
		
		//once more outside of the loop to bring into scope
		BigInteger encrypt = key.encrypt(message);
		BigInteger decrypt = key.decrypt(encrypt);

		//TODO check that message is coprime to the modulus N = pq!!!!
		System.out.println(key);
		System.out.println("\nmessage   = " + message);
		System.out.println("\nencrypted = " + encrypt);
		System.out.println("\ndecrypted = " + decrypt);
	}
}