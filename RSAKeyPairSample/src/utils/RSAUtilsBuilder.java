package utils;

import java.security.NoSuchAlgorithmException;

public class RSAUtilsBuilder {
	private int keySize;
	private String algorithm;
	private String externalPrivateKey;

	public RSAUtilsBuilder algorithm(String algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	public RSAUtilsBuilder keySize(int keySize) {
		this.keySize = keySize;
		return this;
	}
	
	public RSAUtilsBuilder externalPrivateKey(String externalPrivateKey) {
		this.externalPrivateKey = externalPrivateKey;
		return this;
	}

	public RSAUtils build() {
		RSAUtils aRsaUtils = null;
		if (this.algorithm == null) {
			throw new RuntimeException("You must define an Algorithm");
		}

		if (this.keySize == 0) {
			throw new RuntimeException("You must define a keysize");
		}

		try {
			aRsaUtils = this.externalPrivateKey == null 
					? new RSAUtils(this.algorithm, this.keySize) 
					: new RSAUtils(this.algorithm, this.keySize, this.externalPrivateKey);
					
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.toString());
		}
		
		return aRsaUtils;
	}
}
