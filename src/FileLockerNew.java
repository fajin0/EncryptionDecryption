import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

public class FileLockerNew {	
	public static void main(String[] args)  {
//		try {
//			//加密测试代码
//			CipherMetaData metaData = new CipherMetaData("AES", "ECB", "PKCS5Padding", 16, 16);
//			String plainFile = "C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop\\明文文件.txt";
//			String cipherFile = "C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop\\加密文件.txt";
//			String passwd = "123456";
//			new FileLockerNew().encryptFile(metaData, passwd, plainFile, cipherFile);
//			
//			//解密测试代码		
//			String plainFile = "C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop\\明文文件.txt";
//			String cipherFile = "C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop\\加密文件.txt";
//			String passwd = "123456";
//			new FileLockerNew().decryptFile(passwd, plainFile, cipherFile);
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}
	
	private SecretKey getKey(byte[] digestValue, String algorithm, int keyLength) {
		byte[] keyValue = new byte[keyLength];
		keyValue = Arrays.copyOfRange(digestValue, 0, keyLength);//数组切片，拷贝
		return new SecretKeySpec(keyValue, algorithm);
	}
	
	private IvParameterSpec getIv(byte[] digestValue, int blockLength) {
		byte[] ivValue = new byte[blockLength];
		ivValue = Arrays.copyOfRange(digestValue, digestValue.length-1-blockLength, digestValue.length-1);
		return new IvParameterSpec(ivValue);
	}
	
	public void encryptFile(CipherMetaData metaData, 
			String passwd, 
			String plainFile,
			String cipherFile) {
		// 入口参数检查，从略		
		try {
			byte[] digestValue = MessageDigest.getInstance("SHA3-512").digest(passwd.getBytes());
			SecretKey key = getKey(digestValue, metaData.getAlgorithm(), metaData.getKeyLength());
			Cipher cipher = null;
			if(metaData.getAlgorithm().equals("RC4"))
			{
				cipher = Cipher.getInstance(metaData.getAlgorithm());
				cipher.init(Cipher.ENCRYPT_MODE, key);
			}
			else
			{
				cipher = Cipher.getInstance(metaData.getTransformation());
				if(metaData.getMode().equals("ECB"))
				{
					cipher.init(Cipher.ENCRYPT_MODE, key);
				}
				else
				{
					IvParameterSpec iv = getIv(digestValue, metaData.getBlockLength());
					cipher.init(Cipher.ENCRYPT_MODE, key, iv); 
				}		
			}
			FileInputStream fis = new FileInputStream(plainFile);
			FileOutputStream fos = new FileOutputStream(cipherFile);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			CipherInputStream cis = new CipherInputStream(fis, cipher);
			try(oos;cis) {
				oos.writeObject(metaData);		
				cis.transferTo(fos);
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
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
	
	public void decryptFile(String passwd, 
			String plainFile,
			String cipherFile) {
		try {
			FileInputStream fis = new FileInputStream(cipherFile);
			ObjectInputStream ois = new ObjectInputStream(fis);
			FileOutputStream fos = new FileOutputStream(plainFile);
			CipherMetaData metaData = (CipherMetaData) ois.readObject();
			byte[] digestValue = MessageDigest.getInstance("SHA3-512").digest(passwd.getBytes());
			SecretKey key = getKey(digestValue, metaData.getAlgorithm(), metaData.getKeyLength());
			Cipher cipher = null;
			if(metaData.getAlgorithm().equals("RC4"))
			{
				cipher = Cipher.getInstance(metaData.getAlgorithm());
				cipher.init(Cipher.DECRYPT_MODE, key);
			}
			else 
			{
				cipher = Cipher.getInstance(metaData.getTransformation());
				if(metaData.getMode().equals("ECB"))
				{
					cipher.init(Cipher.DECRYPT_MODE, key);
				}
				else
				{
					IvParameterSpec iv = getIv(digestValue, metaData.getBlockLength());		
					cipher.init(Cipher.DECRYPT_MODE, key, iv); 
				}	
			}
			CipherInputStream cis = new CipherInputStream(fis, cipher);
			try(cis;fos) {
				cis.transferTo(fos);
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
