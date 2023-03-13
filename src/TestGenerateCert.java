
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TestGenerateCert {
	public static Certificate selfSign(KeyPair keyPair, String subjectDN, String signatureAlgorithm) {
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Certificate reCertificate = null;
		Security.addProvider(bcProvider);	
		long now = System.currentTimeMillis();
		Date startDate = new Date(now);
		X500Name dnName = new X500Name(subjectDN);
		BigInteger certSerialNumber = new BigInteger(Long.toString(now));
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, 1);
		Date endDate = calendar.getTime();
		try {
			ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate,
					endDate, dnName, keyPair.getPublic());
			BasicConstraints basicConstraints = new BasicConstraints(true);
			certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
			reCertificate = new JcaX509CertificateConverter().setProvider(bcProvider)
					.getCertificate(certBuilder.build(contentSigner));
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertIOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return reCertificate;
	}
	public static void main(String[] args) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		String subjectDN = "CN = jin OU = 计算机学院  O = cauc L = tj S = tj C = cn";
		String signatureAlgorithm = "SHA256WithRSA";
		Certificate certificate = selfSign(keyPair, subjectDN, signatureAlgorithm);
		System.out.println(certificate); 
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		char[] passWord = "123456".toCharArray();
		keyStore.load(null, passWord);
		keyStore.setKeyEntry("myrsakey", keyPair.getPrivate(),
				passWord, new Certificate[] { certificate });
		FileOutputStream fos = new FileOutputStream("mynewkeys.keystore");
		keyStore.store(fos, passWord);
	}
}