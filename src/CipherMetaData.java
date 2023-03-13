import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class CipherMetaData implements Serializable{

	private String algorithm;
	private String mode;
	private String padding;
	private int keyLength;
	private int blockLength;
	public CipherMetaData(String algorithm, String mode, String padding, int keyLength, int blockLength) {
		this.algorithm = algorithm;
		this.mode = mode;
		this.padding = padding;
		this.keyLength = keyLength;
		this.blockLength = blockLength;		
	}
	
	public String getAlgorithm() {
		return algorithm;
	}
	public String getMode() {
		return mode;
	}
	public int getKeyLength() {
		return keyLength;
	}
	public int getBlockLength() {
		return blockLength;
	}
	
	public String getTransformation() {
		return algorithm + "/" + mode + "/" + padding;
	}
	@Override
	public String toString() {
		return "CipherMetaData [algorithm=" + algorithm + ", mode=" + mode + ", padding=" + padding + ", keyLength="
				+ keyLength + ", blockLength=" + blockLength + "]";
	}
	public static void main(String[] args) {
		try {
			CipherMetaData metaData = new CipherMetaData("AES", "EECB", "PKCS5Padding", 16, 16);
			FileOutputStream fos = new FileOutputStream("C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop\\明文文件.txt");																				
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			try(oos){
				oos.writeObject(metaData);
			}
			FileInputStream fis = new FileInputStream("C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop\\明文文件.txt");
			ObjectInputStream  ois = new ObjectInputStream(fis);
			try(ois){
				CipherMetaData metaData1 = (CipherMetaData) ois.readObject();
				System.out.println(metaData1.toString());
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
}
