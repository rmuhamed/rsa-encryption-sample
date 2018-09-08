package com.gft.rsa.sample;

import utils.RSAUtils;
import utils.RSAUtilsBuilder;

public class RSAEncryptionSample {
	private static final String ENCRYPTED_MESSAGE = "CHXJ5OH7kUP4aAkhbO4nYPVfNd1xr2B/3CtxMWb1s7x8BN0C/rsTUW2YU4bUSS3YSMDs7o5iz1+x4HIaYG9IXveZmAvbmIDY2BXjpnyqBb+nuuQkHCRG9IIetIIAGqQV3V4aqjQKgMQ9JxnOH43lDHGC/Nrlirw82VXjTpVzLiktvBzEFrZjVu3gPPl4ocL4q6YbEb5FWDVVQS7D+LuXfO1DryQG38j0sgfAnzRWGxNdncKa4+/xN4E+PNVx5zefxsb+v28xgBoPQ4QKqg4DtZfuiN5tFXgY3ddATcMvcIEIM8B3n3nK3J4EZoZ1PiDxBv23xTIG6ubwllJwdWPDVQ==";
//	private static final String EXTERNAL_PRIVATE_KEY = "MIIEpAIBAAKCAQEAy6FYL1ksLrHa8XV6L5Y4bKSLjli1BaqVFGZ4kM4IISuKKEyc68yav2AXmU54uSiy4OKE7dsnlfu+WwGUHbv1WF2b6fugEEMAoTdfVV81uuc/9M4eaVrh/EK1/aPADQyTqf1EY1Ip2mmrZAy6TNfNA5wFMlLayMKVwrvnrZHKB7DCHUJA4I0IdDp4DKykSuIly6+Jf+JPb5Hnitk65TZ0l27tYhok4H3daybt4TeS2o++UPA1ANhvq2xlVrlUiunxWzSF2dyCj6n7S+LksuvTPXH9D7QebHKiAmSMvQbH2HI1Cp4MpvLN1+1uvdyi2TwWq8JpOB6eXJ+RLA4MXpBviwIDAQABAoIBABhK+tTHPCSj9j1JKRcFQlz/smB8h7gR1jA1W1vXIJQoeBZ/sVbWNX3wTlBtUqywRMrca0RfGVVkz5xWz19OvaHZpRCggsN94tTY4Mg0EBponTIs5ublv0ETilekkfRclD865k49Dp4ubhKFDDK/qgcstVgAF3bM9AXj2etUkbgh8QdtyV44JoIJQ8irUxoXDEN4t61lYeEvxT/EnTh/yem6fE3ytBqgEC5vZGAQpAEP+i2m4tA7xvi4EbtC1i0yvrWHfmzkvQqPfAfiJ05zvgGHwgYbrPSCdIMjADu+wF+OzselcLwetIOUYVr4MadCgCK0nBAt95ni44vBOsIN5ZkCgYEA+q35TTgvtM5sysdIx0o+1V9Nzemihmx70wIImdnEB7GYGneXfd6eWHwuVXP7jFwgU0Z8MCVkXtdldeL1geqfrPTbXmemUEmU3ClOClR3oxmL1LswEo5/1CyANxlrGxFwzab2Ep3d+r89d4SoHnrxZNTI0UtM1XLZNo8bQE2tSrkCgYEAz/O8YILXNF9EMguk/w7PicWXHXfL3dFgr9lRV3ORpgiVKDJuBc2xIQTKsjaNqts6pSe5I+jwwpsNndRvnDTUpDqpozORuy2fbKh6MbDRIUhM61F21SGZHuMvYqmmT/2IZD9afqAs2nyrzzukk1Ej9pv/P8nIm42Be0kmg5jD2mMCgYEAr2sxCtVnpOnS/a+pATS2dZAEnTSCM/kUSVuh8y+NWyju3I6Vp1Iyko8LyWapP9Z0FHI9k1+HNksax/zzel9aL6kFHbIAkyx6i/onj1j+g1bsIAiBomqvjyU479XMuptgybitd+ebH83V0J43G2VDKSEyCivcb323/NL16fCxdJkCgYBrvAmvMnoN3wE0sEW2AlVROjX1BVhwPgZKdFso5G3jx/SGk8HebddDlPjyZUL17ogugirvyMHbAHuIdkOweMplnyK9s3zfrV436/0Ke2GNTajUDSt0deifUPH+uoe4T1B3Jz9Z9N/n/ckBHxQ/Yj0wiVcvE/pDZIddeONkMCPfowKBgQDEt+jTvI0dwjXMOezE0cjCtu7YEJJWataNPJE4DbGMeKPVqgbwn5zUwFv0S4mz/Mx0eX0r/vUTB3EvORZg0wfzM+luv1nXqNw4uu8kiKrtnUsKPX0afvRpuXCAa8rgM4Alv6pXD0E4nme7M0BlgWjkkh5MRCw+PkNjgWYqzLVd3A==";
			
	public static void main(String[] args) {		
		RSAUtilsBuilder builder = new RSAUtilsBuilder();
		builder.algorithm("RSA");
		builder.keySize(2048);
		RSAUtils rsa = builder.build();
		
		try {
			String encrypted = rsa.encrypt("Un mensaje de prueba");
	
			System.out.println("Encrypted result");
			System.out.println(encrypted);
			
			System.out.println("Decrypted result");
			System.out.println(rsa.decrypt(encrypted));
			
			System.out.println("Private Key generated");
			System.out.println(rsa.getPrivateKeyAsBase64());
			System.out.println("Public Key generated");
			System.out.println(rsa.getPublicKeyAsBase64());
		} catch (Exception e) {
			System.err.println(e.toString());
		}	
	}

	private static String format(String externalPrivateKey) {
		StringBuilder sb = new StringBuilder();
		sb.append("-----BEGIN RSA PRIVATE KEY-----");
		sb.append('\n');
		sb.append(externalPrivateKey);
		sb.append('\n');
		sb.append("-----END RSA PRIVATE KEY-----");
		return sb.toString();
	}
}
