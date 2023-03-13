import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.util.encoders.Hex;

public class TextFileSign {
//	public static void main(String[] args) throws Exception {
//		String file = "aaa.txt";
//		String signValueFile = "aaa.txt.sign";
//		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//		KeyPair keyPair = generator.generateKeyPair();
//		PrivateKey privateKey = keyPair.getPrivate();
//		PublicKey publicKey = keyPair.getPublic();
//		signFile(file, privateKey, signValueFile,"RSA");
//		System.out.println(verifyFile(file, publicKey, signValueFile,"RSA"));
//	}

	public static void signFile(String fileToSign, PrivateKey key, String signValueFile , String algorithm) {
		try {
			try (FileInputStream fis = new FileInputStream(fileToSign);
					FileOutputStream fos = new FileOutputStream(signValueFile,true)) {
				Signature signature = Signature.getInstance("SHA256with" + algorithm);
				signature.initSign(key);
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fis.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				byte[] signaturValue = signature.sign();
				fos.write(signaturValue);
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static boolean verifyFile(String fileToVerify, PublicKey key, String signValueFile, String algorithm) {
		boolean value = false;
		try {
			try (FileInputStream fisFileToVerify = new FileInputStream(fileToVerify);
					FileInputStream fisSignValueFile = new FileInputStream(signValueFile)) {
				fisSignValueFile.skip(3);
				Signature signature = Signature.getInstance("SHA256with" + algorithm);
				signature.initVerify(key);
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fisFileToVerify.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				byte[] signatureValue = new byte[fisSignValueFile.available()];
				fisSignValueFile.read(signatureValue);
				value = signature.verify(signatureValue);
				
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return value;
	}
}