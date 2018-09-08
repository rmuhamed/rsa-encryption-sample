package utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public final class RSAUtils {
	private static final String TRANSFORMATION = "RSA";

	final static String ENCODING = "UTF8"; 

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private String algorithm;
	private int keySize;

	RSAUtils(String algorithm, int keySize) throws NoSuchAlgorithmException {
		this.algorithm = algorithm;
		this.keySize = keySize;
		
		KeyPair aKeyPair = this.init();
		
		this.privateKey = this.generatePrivateFrom(aKeyPair);
		this.publicKey = this.generatePublicFrom(aKeyPair);
	}
	
	RSAUtils(String algorithm, int keySize, String externalPrivateKey) {
		this.algorithm = algorithm;
		this.keySize = keySize;
		
		this.privateKey = this.generatePrivateFrom(externalPrivateKey);
	}

	public String getPublicKeyAsBase64() {
		return Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
	}
	
	public String getPrivateKeyAsBase64() {
		return Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
	}

	public String encrypt(String originalMessage) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
		
		return Base64.getEncoder().encodeToString(cipher.doFinal(originalMessage.getBytes()));
	}
	
	public String decrypt(String encryptedMessage) throws Exception {	
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

		byte[] cipherText = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage.getBytes()));		
	
		return new String(cipherText, ENCODING);
	}
	
	//******************************************************************************/
	private KeyPair init() throws NoSuchAlgorithmException {
		KeyPairGenerator aKeyGenerator = KeyPairGenerator.getInstance(this.algorithm);
		aKeyGenerator.initialize(this.keySize);
		return aKeyGenerator.generateKeyPair();
	}
	
	private PublicKey generatePublicFrom(KeyPair aKeyPair) {
		return aKeyPair.getPublic();
	}
	
	private PrivateKey generatePrivateFrom(KeyPair aKeyPair) {
		return aKeyPair.getPrivate();
	}
	
	private PrivateKey generatePrivateFrom(String externalPrivateKey) {				
		PrivateKey generatedPrivateKey = null;
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance(this.algorithm);
			byte[] encodedBytes = Base64.getEncoder().encode(externalPrivateKey.getBytes());
			byte[] privKeyBytes = Base64.getDecoder().decode(new String(encodedBytes).getBytes("UTF-8"));
			
			PKCS8EncodedKeySpec privateEncodedKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
			generatedPrivateKey = keyFactory.generatePrivate(privateEncodedKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | UnsupportedEncodingException e) {
			System.err.println(e.getMessage());
		}
		
		return generatedPrivateKey;
	}
	//******************************************************************************/
}
