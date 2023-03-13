import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.HeadlessException;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.JTabbedPane;
import javax.swing.JLabel;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextPane;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;
import java.awt.Font;
import javax.swing.border.BevelBorder;
import javax.swing.JRadioButton;

public class IntegradeTool extends JFrame {

	private JPanel contentPane;
	private JTextField textFieldInput;
	private JTextField textFieldSHA1;
	private JTextField textFieldSHA224;
	private JTextField textFieldMD5;
	private JTextField textFieldSHA256;
	private JTextField textFieldSHA384;
	private JTextField textFieldSHA512;
	private JTextField textFieldSHA3224;
	private JTextField textFieldSHA3256;
	private JTextField textFieldSHA3384;
	private JTextField textFieldSHA3512;
	private JTextField textFieldFileSource;
	private JTextField textFieldPassword;
	private JTextField textFieldFile;
	private JTextField textFieldPasswd;
	private JTextField textFieldResult;
	private JTextField textFieldSM3;

	private File plainfile = null;//充当明文文件/签名文件
	private File cipherfile = null;//充当密文文件/待验证文件
	private String[] algorithms = {"AES","DESede","DES","SM4","RC4"};
	private String[] modes = {"ECB","CBC","CFB","OFB","CTR"};
	private String[] paddings = {"PKCS5Padding","ISO10126Padding","NoPadding"};
	private int[] keyLength = {0,24,8,16,16};
	private int[] blockLength = {16,8,8,16,0};
	private int[] aeskeyLength = {16,24,32};
	private JFileChooser fileChooser = new JFileChooser(
			"C:\\Users\\Administrator.ZJZL-20180830YA\\Desktop");//桌面路径
	private JTextField textFieldSignfileSource;
	private JTextField textFieldVerfile;
	private JTextField textFieldSignfile;
	private JTextField textFieldPassWord;
	private JTextField textFieldDataField;
	private JTextField textFieldGPassword;
	private JTextField textFieldMMD5;
	private JTextField textFieldMSHA1;
	private JTextField textFieldMSHA224;
	private JTextField textFieldMSHA256;
	private JTextField textFieldMSHA384;
	private JTextField textFieldMSHA512;
	private JTextField textFieldMSHA3224;
	private JTextField textFieldMSHA3256;
	private JTextField textFieldMSHA3384;
	private JTextField textFieldMSHA3512;
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					IntegradeTool frame = new IntegradeTool();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public IntegradeTool() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 534, 440);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane, BorderLayout.CENTER);
		
		JPanel panelHash = new JPanel();
		tabbedPane.addTab("Hash", null, panelHash, null);
		panelHash.setLayout(null);
		
		JButton btnFileSource = new JButton("\u6D4F\u89C8");
		btnFileSource.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				plainfile = null;
				int returnVal = fileChooser.showOpenDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION) {//选择文件
					plainfile = fileChooser.getSelectedFile();
					textFieldInput.setText(plainfile.getAbsolutePath());
				}
				else {
					return;
				}
			}
		});
		btnFileSource.setBounds(404, 10, 67, 23);
		panelHash.add(btnFileSource);
		
		textFieldInput = new JTextField();
		textFieldInput.setBounds(100, 11, 294, 21);
		panelHash.add(textFieldInput);
		textFieldInput.setColumns(10);
		
		JComboBox comboBoxType = new JComboBox();
		comboBoxType.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {//界面显示控制
				if(comboBoxType.getSelectedIndex() == 1) {
					textFieldInput.setText("");
					btnFileSource.setVisible(false);
					textFieldInput.setSize(371, 21);
				}
				else {
					textFieldInput.setText("");
					btnFileSource.setVisible(true);
					textFieldInput.setSize(294, 21);
				}
			}
		});
		comboBoxType.setFont(new Font("Arial Black", Font.PLAIN, 12));
		comboBoxType.setModel(new DefaultComboBoxModel(new String[] {"File", "String"}));
		comboBoxType.setBounds(10, 10, 72, 23);
		panelHash.add(comboBoxType);
		
		JCheckBox chckMD5 = new JCheckBox("MD5");
		chckMD5.setFont(new Font("Arial", Font.PLAIN, 12));
		chckMD5.setBounds(6, 39, 88, 23);
		panelHash.add(chckMD5);
		
		JCheckBox chckSHA1 = new JCheckBox("SHA1");
		chckSHA1.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA1.setBounds(6, 64, 88, 23);
		panelHash.add(chckSHA1);
		
		JCheckBox chckSHA224 = new JCheckBox("SHA224");
		chckSHA224.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA224.setBounds(6, 90, 88, 23);
		panelHash.add(chckSHA224);
		
		JCheckBox chckSHA256 = new JCheckBox("SHA256");
		chckSHA256.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA256.setBounds(6, 115, 88, 23);
		panelHash.add(chckSHA256);
		
		JCheckBox chckSHA384 = new JCheckBox("SHA384");
		chckSHA384.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA384.setBounds(6, 140, 84, 23);
		panelHash.add(chckSHA384);
		
		JCheckBox chckSHA512 = new JCheckBox("SHA512");
		chckSHA512.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA512.setBounds(6, 164, 88, 23);
		panelHash.add(chckSHA512);
		
		JCheckBox chckSHA3224 = new JCheckBox("SHA3-224");
		chckSHA3224.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA3224.setBounds(6, 189, 88, 23);
		panelHash.add(chckSHA3224);
		
		JCheckBox chckSHA3256 = new JCheckBox("SHA3-256");
		chckSHA3256.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA3256.setBounds(6, 213, 88, 23);
		panelHash.add(chckSHA3256);
		
		JCheckBox chckSHA3384 = new JCheckBox("SHA3-384");
		chckSHA3384.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA3384.setBounds(6, 238, 88, 23);
		panelHash.add(chckSHA3384);
		
		JCheckBox chckSHA3512 = new JCheckBox("SHA3-512");
		chckSHA3512.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSHA3512.setBounds(6, 263, 88, 23);
		panelHash.add(chckSHA3512);
		
		JCheckBox chckSM3 = new JCheckBox("SM3");
		chckSM3.setFont(new Font("Arial", Font.PLAIN, 12));
		chckSM3.setBounds(6, 291, 88, 23);
		panelHash.add(chckSM3);
		
		textFieldMD5 = new JTextField();
		textFieldMD5.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldMD5.setEditable(false);
		textFieldMD5.setBounds(100, 40, 371, 21);
		panelHash.add(textFieldMD5);
		textFieldMD5.setColumns(10);
		
		textFieldSHA1 = new JTextField();
		textFieldSHA1.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA1.setEditable(false);
		textFieldSHA1.setBounds(100, 65, 371, 21);
		panelHash.add(textFieldSHA1);
		textFieldSHA1.setColumns(10);
		
		textFieldSHA224 = new JTextField();
		textFieldSHA224.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA224.setEditable(false);
		textFieldSHA224.setBounds(100, 91, 371, 21);
		panelHash.add(textFieldSHA224);
		textFieldSHA224.setColumns(10);
		
		textFieldSHA256 = new JTextField();
		textFieldSHA256.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA256.setEditable(false);
		textFieldSHA256.setBounds(100, 116, 371, 21);
		panelHash.add(textFieldSHA256);
		textFieldSHA256.setColumns(10);
		
		textFieldSHA384 = new JTextField();
		textFieldSHA384.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA384.setEditable(false);
		textFieldSHA384.setColumns(10);
		textFieldSHA384.setBounds(100, 142, 371, 21);
		panelHash.add(textFieldSHA384);
		
		textFieldSHA512 = new JTextField();
		textFieldSHA512.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA512.setEditable(false);
		textFieldSHA512.setColumns(10);
		textFieldSHA512.setBounds(100, 166, 371, 21);
		panelHash.add(textFieldSHA512);
		
		textFieldSHA3224 = new JTextField();
		textFieldSHA3224.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA3224.setEditable(false);
		textFieldSHA3224.setColumns(10);
		textFieldSHA3224.setBounds(100, 190, 371, 21);
		panelHash.add(textFieldSHA3224);
		
		textFieldSHA3256 = new JTextField();
		textFieldSHA3256.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA3256.setEditable(false);
		textFieldSHA3256.setColumns(10);
		textFieldSHA3256.setBounds(100, 214, 371, 21);
		panelHash.add(textFieldSHA3256);
		
		textFieldSHA3384 = new JTextField();
		textFieldSHA3384.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA3384.setEditable(false);
		textFieldSHA3384.setColumns(10);
		textFieldSHA3384.setBounds(100, 239, 371, 21);
		panelHash.add(textFieldSHA3384);
		
		textFieldSHA3512 = new JTextField();
		textFieldSHA3512.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSHA3512.setEditable(false);
		textFieldSHA3512.setColumns(10);
		textFieldSHA3512.setBounds(100, 264, 371, 21);
		panelHash.add(textFieldSHA3512);
		
		JButton buttonCalculate = new JButton("\u8BA1\u7B97");
		buttonCalculate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {//计算Hah值
				try {
					Security.addProvider(new BouncyCastleProvider());//加BouncyCastle库，其中包含SM3hash算法
					JCheckBox[] jCheckBox = {chckMD5,chckSHA1,chckSHA224,chckSHA256,chckSHA384,chckSHA512,chckSHA3224,chckSHA3256,chckSHA3384,chckSHA3512,chckSM3};
					JTextField[] jTextField = {textFieldMD5,textFieldSHA1,textFieldSHA224,textFieldSHA256,textFieldSHA384,textFieldSHA512,textFieldSHA3224,textFieldSHA3256,textFieldSHA3384,textFieldSHA3512,textFieldSM3};
					String[] hashNames = {"MD5","SHA1","SHA-224","SHA-256","SHA-384","SHA-512","SHA3-224","SHA3-256","SHA3-384","SHA3-512","SM3"};
					if(comboBoxType.getSelectedIndex()==1) {/*如果选择是字符串HASH计算*/
						for(int i = 0;i < hashNames.length;i++) {
							if(jCheckBox[i].isSelected()) {
								MessageDigest md = MessageDigest.getInstance(hashNames[i]);
								String s = textFieldInput.getText();
								md.update(s.getBytes());
								jTextField[i].setText(Hex.toHexString(md.digest()));//输出字符串的Hash值
							}
							else {
								jTextField[i].setText("");
							}
						}
					}
					else {/*如果选择是文件HASH计算*/
						FileInputStream fis = new FileInputStream(plainfile);
							for(int i = 0;i < hashNames.length;i++) {
								if(jCheckBox[i].isSelected()) {
									byte[] buffer = new byte[1024];
									int n = -1;
									MessageDigest md = MessageDigest.getInstance(hashNames[i]);
									while((n = fis.read(buffer)) != -1) {
										md.update(buffer,0 ,n);
									}
									jTextField[i].setText(Hex.toHexString(md.digest()));
								}
								else {
									jTextField[i].setText("");
								}
						}
					}
				} catch (HeadlessException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
				
			}
		});
		
		textFieldSM3 = new JTextField();
		textFieldSM3.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSM3.setEditable(false);
		textFieldSM3.setBounds(100, 292, 371, 21);
		panelHash.add(textFieldSM3);
		textFieldSM3.setColumns(10);
		buttonCalculate.setBounds(132, 329, 93, 23);
		panelHash.add(buttonCalculate);
		
		JButton buttonClear = new JButton("\u6E05\u7A7A");
		buttonClear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {/*清空文本框*/
				JCheckBox[] jCheckBox = {chckMD5,chckSHA1,chckSHA224,chckSHA256,chckSHA384,chckSHA512,chckSHA3224,chckSHA3256,chckSHA3384,chckSHA3512,chckSM3};
				JTextField[] jTextField = {textFieldMD5,textFieldSHA1,textFieldSHA224,textFieldSHA256,textFieldSHA384,textFieldSHA512,textFieldSHA3224,textFieldSHA3256,textFieldSHA3384,textFieldSHA3512,textFieldSM3};
				for(int i = 0;i < jCheckBox.length;i++) {
					if(jCheckBox[i].isSelected())
						jTextField[i].setText("");
				}
			}
		});
		buttonClear.setBounds(262, 329, 93, 23);
		panelHash.add(buttonClear);
		
		JButton buttonClose = new JButton("\u5173\u95ED");
		buttonClose.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		buttonClose.setBounds(378, 329, 93, 23);
		panelHash.add(buttonClose);
		
		JPanel panelSymmetic = new JPanel();
		tabbedPane.addTab("\u5BF9\u79F0\u52A0\u5BC6\u7B97\u6CD5", null, panelSymmetic, null);
		panelSymmetic.setLayout(null);
		
		JLabel lblAlgorithm = new JLabel("ALGORITHM");
		lblAlgorithm.setFont(new Font("Baskerville Old Face", Font.PLAIN, 12));
		lblAlgorithm.setBounds(31, 12, 82, 15);
		panelSymmetic.add(lblAlgorithm);
		
		JLabel lblLength = new JLabel("AESKEYLENGTH");
		lblLength.setFont(new Font("Baskerville Old Face", Font.PLAIN, 12));
		lblLength.setVerticalAlignment(SwingConstants.BOTTOM);
		lblLength.setBounds(131, 10, 101, 15);
		panelSymmetic.add(lblLength);
		
		JLabel lblMode = new JLabel("   MODE");
		lblMode.setFont(new Font("Baskerville Old Face", Font.PLAIN, 12));
		lblMode.setBounds(242, 10, 54, 15);
		panelSymmetic.add(lblMode);
		
		JLabel lblPadding = new JLabel("PADDING");
		lblPadding.setFont(new Font("Baskerville Old Face", Font.PLAIN, 12));
		lblPadding.setBounds(370, 12, 66, 15);
		panelSymmetic.add(lblPadding);
		
		JComboBox comboBoxKeyLength = new JComboBox();
		comboBoxKeyLength.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboBoxKeyLength.setModel(new DefaultComboBoxModel(new String[] {"128", "192", "256"}));
		comboBoxKeyLength.setBounds(146, 33, 66, 23);
		panelSymmetic.add(comboBoxKeyLength);
		
		JComboBox comboBoxPadding = new JComboBox();
		comboBoxPadding.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboBoxPadding.setModel(new DefaultComboBoxModel(new String[] {"PKCS5Padd", "ISO10126P", "NoPadding"}));
		comboBoxPadding.setBounds(344, 33, 115, 23);
		panelSymmetic.add(comboBoxPadding);
		
		JComboBox comboBoxMode = new JComboBox();
		comboBoxMode.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboBoxMode.setModel(new DefaultComboBoxModel(new String[] {"ECB", "CBC", "CFB", "OFB", "CTR"}));
		comboBoxMode.setBounds(242, 33, 66, 23);
		panelSymmetic.add(comboBoxMode);
		
		JComboBox comboBoxAlgorithm = new JComboBox();
		comboBoxAlgorithm.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {/*界面控制*/
				if(comboBoxAlgorithm.getSelectedIndex() != 0) {
					comboBoxKeyLength.setVisible(false);
				}
				if(comboBoxAlgorithm.getSelectedIndex() == 4) {
					comboBoxKeyLength.setVisible(false);
					comboBoxMode.setVisible(false);
					comboBoxPadding.setVisible(false);
				}
				if(comboBoxAlgorithm.getSelectedIndex() == 0) {
					comboBoxKeyLength.setVisible(true);
					comboBoxMode.setVisible(true);
					comboBoxPadding.setVisible(true);
				}
			}
		});
		
		comboBoxAlgorithm.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboBoxAlgorithm.setModel(new DefaultComboBoxModel(new String[] {"AES", "3DES", "DES", "SM4", "RC4"}));
		comboBoxAlgorithm.setBounds(37, 33, 66, 23);
		panelSymmetic.add(comboBoxAlgorithm);
		
		JLabel lblData = new JLabel("File");
		lblData.setFont(new Font("Baskerville Old Face", Font.PLAIN, 12));
		lblData.setBounds(37, 82, 43, 23);
		panelSymmetic.add(lblData);
		
		JButton buttonSearch = new JButton("\u6D4F\u89C8");
		buttonSearch.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				plainfile = null;
				int returnVal = fileChooser.showOpenDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION) {/*选择文件进行加密或者解密*/
					plainfile = fileChooser.getSelectedFile();
					textFieldFileSource.setText(plainfile.getAbsolutePath());
				}
				else {
					return;
				}
			}
		});
		
		textFieldFileSource = new JTextField();
		textFieldFileSource.setEditable(false);
		textFieldFileSource.setBounds(87, 83, 318, 21);
		panelSymmetic.add(textFieldFileSource);
		textFieldFileSource.setColumns(10);
		buttonSearch.setBounds(410, 82, 66, 23);
		panelSymmetic.add(buttonSearch);
		
		JLabel labelPassword = new JLabel("Password");
		labelPassword.setFont(new Font("Baskerville Old Face", Font.PLAIN, 14));
		labelPassword.setBounds(20, 132, 60, 23);
		panelSymmetic.add(labelPassword);
		
		textFieldPassword = new JTextField();
		textFieldPassword.setColumns(10);
		textFieldPassword.setBounds(87, 132, 389, 21);
		panelSymmetic.add(textFieldPassword);
		
		JButton buttonDecrypt = new JButton("\u89E3\u5BC6");
		buttonDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
					int returnVal = fileChooser.showSaveDialog(null);
					if(returnVal == JFileChooser.APPROVE_OPTION)/*选择解密后文件存储位置*/
					{
						cipherfile = fileChooser.getSelectedFile();
					}
					else return;
					
					if(plainfile.isFile())
					{
						String passwd = textFieldPassword.getText();
						try {
							new FileLockerNew().decryptFile(passwd, cipherfile.toString(), plainfile.toString());
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
					}	
			}
		});
		
		JButton buttonEncrypt = new JButton("\u52A0\u5BC6");
		buttonEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {		
				int returnVal = fileChooser.showSaveDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION)/*选择加密后文件存储位置*/
				{
					cipherfile = fileChooser.getSelectedFile();
					textFieldFileSource.setText(cipherfile.getAbsolutePath());
				}
				else return;
				
				if(plainfile.isFile())
				{/*获得加密算法，密钥长度，分组模式以及填充模式*/
					int algorithm = comboBoxAlgorithm.getSelectedIndex();
					int mode = comboBoxMode.getSelectedIndex();
					int pad = comboBoxPadding.getSelectedIndex();
					int optionAES = 0;
					if(algorithm == 0){/*确定AES加密密钥长度*/
						optionAES = comboBoxKeyLength.getSelectedIndex();
						keyLength[0] = aeskeyLength[optionAES];
					}
					CipherMetaData metaData = null;
					if(algorithm == 4){/*流密码RC4算法不需要分组和填充*/
						metaData = new CipherMetaData(algorithms[algorithm], "", "", keyLength[algorithm], blockLength[algorithm]);
					}
					else {
						metaData = new CipherMetaData(algorithms[algorithm], 
								modes[mode], paddings[pad], keyLength[algorithm],
								blockLength[algorithm]);
					}				
					String passwd = textFieldPassword.getText();
					try {
						new FileLockerNew().encryptFile(metaData, passwd, plainfile.toString(), cipherfile.toString());
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}
		});
		buttonEncrypt.setBounds(96, 298, 93, 23);
		panelSymmetic.add(buttonEncrypt);
		buttonDecrypt.setBounds(242, 298, 93, 23);
		panelSymmetic.add(buttonDecrypt);
		
		JButton buttonclose = new JButton("\u5173\u95ED");
		buttonclose.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		buttonclose.setBounds(383, 298, 93, 23);
		panelSymmetic.add(buttonclose);
		
		JPanel panelDataSignature = new JPanel();
		tabbedPane.addTab("\u6570\u5B57\u7B7E\u540D", null, panelDataSignature, null);
		panelDataSignature.setLayout(null);
		
		JLabel lblFile = new JLabel("File");
		lblFile.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		lblFile.setBounds(32, 40, 41, 18);
		panelDataSignature.add(lblFile);
		
		textFieldFile = new JTextField();
		textFieldFile.setFont(new Font("华文中宋", Font.PLAIN, 12));
		textFieldFile.setEditable(false);
		textFieldFile.setBounds(86, 40, 304, 22);
		panelDataSignature.add(textFieldFile);
		textFieldFile.setColumns(10);
		
		JButton buttonSearchFile = new JButton("\u6D4F\u89C8");
		buttonSearchFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				plainfile=null;
				int returnVal = fileChooser.showOpenDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION) {/*选择文件进行签名或者验证操作*/
					plainfile = fileChooser.getSelectedFile();
					textFieldFile.setText(plainfile.getAbsolutePath());
				}
				else {
					return;
				}	
			}
		});
		buttonSearchFile.setBounds(400, 35, 75, 28);
		panelDataSignature.add(buttonSearchFile);
		
		JLabel labelPasswd = new JLabel("Password");
		labelPasswd.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		labelPasswd.setBounds(17, 68, 59, 23);
		panelDataSignature.add(labelPasswd);
		
		textFieldPasswd = new JTextField();
		textFieldPasswd.setFont(new Font("华文中宋", Font.PLAIN, 12));
		textFieldPasswd.setColumns(10);
		textFieldPasswd.setBounds(86, 72, 389, 21);
		panelDataSignature.add(textFieldPasswd);
		
		JLabel lblSignAlgorithm = new JLabel("Algorithm");
		lblSignAlgorithm.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		lblSignAlgorithm.setBounds(14, 101, 59, 15);
		panelDataSignature.add(lblSignAlgorithm);
		
		JComboBox comboAlgorithmSign = new JComboBox();
		comboAlgorithmSign.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboAlgorithmSign.setModel(new DefaultComboBoxModel(new String[] {"DSA", "RSA"}));
		comboAlgorithmSign.setBounds(86, 97, 79, 23);
		panelDataSignature.add(comboAlgorithmSign);
		
		JLabel lblResult = new JLabel("Result");
		lblResult.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		lblResult.setBounds(14, 274, 59, 23);
		panelDataSignature.add(lblResult);
		
		textFieldResult = new JTextField();
		textFieldResult.setFont(new Font("华文中宋", Font.PLAIN, 12));
		textFieldResult.setEditable(false);
		textFieldResult.setBounds(83, 275, 79, 22);
		panelDataSignature.add(textFieldResult);
		textFieldResult.setColumns(10);
		
		JButton btnNewButtonSign = new JButton("\u7B7E\u540D");
		btnNewButtonSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					String algorithm = null;
					if(comboAlgorithmSign.getSelectedIndex() == 0){/*验证算法为DSA*/
						algorithm = "DSA";
					}
					else {/*验证算法为RSA*/
						algorithm ="RSA";
					}
						/*创建随机密钥对生成器*/
						KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
						/*创建密钥对对象*/
						KeyPair keyPair = keyPairGenerator.generateKeyPair();
						String subjectDN = "CN = jin OU = 计算机学院  O = cauc L = tj S = tj C = cn";
						String signatureAlgorithm = "SHA256With" + algorithm;
						/*生成数字证书*/
						Certificate certificate = TestGenerateCert.selfSign(keyPair, subjectDN, signatureAlgorithm);
						KeyStore keyStore = KeyStore.getInstance("PKCS12");
						char[] passWord = textFieldPasswd.getText().toCharArray();
						keyStore.load(null, passWord);
						keyStore.setKeyEntry("my" + algorithm.toLowerCase() + "key", keyPair.getPrivate(),
								passWord, new Certificate[] { certificate });																								//要描述证书链，就必须用证书数组new Certificate[] { certificate }
						FileOutputStream fos = new FileOutputStream("keystore.keystore");
						try(fos){
							keyStore.store(fos, passWord);
						}
						int returnVal = fileChooser.showSaveDialog(null);
						if(returnVal == JFileChooser.APPROVE_OPTION)
						{
							cipherfile = fileChooser.getSelectedFile();
							textFieldSignfileSource.setText(cipherfile.getAbsolutePath());
						}
						else {
							return;
						}
							char[] password = textFieldPasswd.getText().toCharArray();
							FileInputStream fis = new FileInputStream("keystore.keystore");//因为已经拷贝到的项目目录之下，所以不用加路径
							try(fis){
								keyStore.load(fis, password);
								KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);//ProtectionParameter是要设置保护条目的口令
								if(comboAlgorithmSign.getSelectedIndex() == 0)
								{
									FileWriter fileWriter = new FileWriter(cipherfile);
									fileWriter.write("DSA");/*验证算法写入签名值文件*/
									fileWriter.close();
									KeyStore.PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("mydsakey", protParam);//第一个参数是“密钥参数的别名”，第二个参数是“保护参数”
									DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privateKeyEntry.getPrivateKey();
									TextFileSign.signFile(plainfile.toString(), dsaPrivateKey, cipherfile.toString(), "DSA");
								}
								else
								{
									FileWriter fileWriter = new FileWriter(cipherfile);
									fileWriter.write("RSA");/*验证算法写入签名值文件*/
									fileWriter.close();
									KeyStore.PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("myrsakey", protParam);//第一个参数是“密钥参数的别名”，第二个参数是“保护参数”
									RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
									TextFileSign.signFile(plainfile.toString(), rsaPrivateKey, cipherfile.toString(), "RSA");
								}
							}
				} catch (HeadlessException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (KeyStoreException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (CertificateException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (UnrecoverableEntryException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}	
			}
		});
		btnNewButtonSign.setBounds(377, 121, 98, 28);
		panelDataSignature.add(btnNewButtonSign);
		
		JButton btnNewButtonTest = new JButton("\u9A8C\u8BC1");
		btnNewButtonTest.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					KeyStore keyStore = KeyStore.getInstance("PKCS12");
					char[] password = textFieldPassWord.getText().toCharArray();
					FileInputStream fis = new FileInputStream("keystore.keystore");
					try(fis){
						keyStore.load(fis, password);
						byte[] algorithm = new byte[3];
						FileInputStream fisbytearray = new FileInputStream(cipherfile);
						fisbytearray.read(algorithm);
						fisbytearray.close();
						if(algorithm[0] == 'D')
						{
							X509Certificate certificate = (X509Certificate) keyStore.getCertificate("mydsakey");
							DSAPublicKey dsaPublicKey = (DSAPublicKey) certificate.getPublicKey();
							
							if(TextFileSign.verifyFile(plainfile.toString(), dsaPublicKey, cipherfile.toString(), "DSA"))
							{
								textFieldResult.setText("验证通过！");
							}
							else {
								textFieldResult.setText("验证失败！");	
							}
						}
						else{
							X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myrsakey");
							RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
							if(TextFileSign.verifyFile(plainfile.toString(), rsaPublicKey, cipherfile.toString(), "RSA"))
							{
								textFieldResult.setText("验证通过！");
							}
							else {
								textFieldResult.setText("验证失败！");
							}
						}
					if(textFieldResult.getText() == "") {
						textFieldResult.setText("验证失败！");
					}
					}
				} catch (KeyStoreException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (CertificateException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		btnNewButtonTest.setBounds(239, 309, 98, 28);
		panelDataSignature.add(btnNewButtonTest);
		
		JButton buttonClosed = new JButton("\u5173\u95ED");
		buttonClosed.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);//关闭猫
			}
		});
		buttonClosed.setBounds(374, 309, 98, 28);
		panelDataSignature.add(buttonClosed);
		
		JLabel lblSign = new JLabel("Signature");
		lblSign.setFont(new Font("Bell MT", Font.PLAIN, 30));
		lblSign.setBounds(10, 0, 157, 43);
		panelDataSignature.add(lblSign);
		
		textFieldSignfileSource = new JTextField();
		textFieldSignfileSource.setFont(new Font("华文中宋", Font.PLAIN, 12));
		textFieldSignfileSource.setEditable(false);
		textFieldSignfileSource.setColumns(10);
		textFieldSignfileSource.setBounds(24, 126, 347, 22);
		panelDataSignature.add(textFieldSignfileSource);
		
		JLabel labelVerfication = new JLabel("Verification");
		labelVerfication.setFont(new Font("Baskerville Old Face", Font.PLAIN, 30));
		labelVerfication.setBounds(0, 154, 186, 36);
		panelDataSignature.add(labelVerfication);
		
		JLabel labelVerfile = new JLabel("\u5F85\u9A8C\u8BC1\u6587\u4EF6");
		labelVerfile.setFont(new Font("华文中宋", Font.PLAIN, 12));
		labelVerfile.setBounds(10, 185, 63, 18);
		panelDataSignature.add(labelVerfile);
		
		textFieldVerfile = new JTextField();
		textFieldVerfile.setFont(new Font("华文中宋", Font.PLAIN, 12));
		textFieldVerfile.setEditable(false);
		textFieldVerfile.setColumns(10);
		textFieldVerfile.setBounds(83, 185, 304, 22);
		panelDataSignature.add(textFieldVerfile);
		
		JLabel labelSignFile = new JLabel("\u7B7E\u540D\u503C\u6587\u4EF6");
		labelSignFile.setFont(new Font("华文中宋", Font.PLAIN, 12));
		labelSignFile.setBounds(10, 213, 63, 18);
		panelDataSignature.add(labelSignFile);
		
		textFieldSignfile = new JTextField();
		textFieldSignfile.setFont(new Font("华文中宋", Font.PLAIN, 12));
		textFieldSignfile.setEditable(false);
		textFieldSignfile.setColumns(10);
		textFieldSignfile.setBounds(83, 213, 304, 22);
		panelDataSignature.add(textFieldSignfile);
		
		JLabel labelSignPassword = new JLabel("Password");
		labelSignPassword.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		labelSignPassword.setBounds(10, 241, 59, 23);
		panelDataSignature.add(labelSignPassword);
		
		textFieldPassWord = new JTextField();
		textFieldPassWord.setFont(new Font("Baskerville Old Face", Font.PLAIN, 12));
		textFieldPassWord.setColumns(10);
		textFieldPassWord.setBounds(83, 244, 392, 21);
		panelDataSignature.add(textFieldPassWord);
		
		JButton buttonOpenCfile = new JButton("\u6D4F\u89C8");
		buttonOpenCfile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				plainfile=null;
				int returnVal = fileChooser.showSaveDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION) {
					plainfile = fileChooser.getSelectedFile();
					textFieldVerfile.setText(plainfile.getAbsolutePath());
				}
				else {
					return;
				}	
			}
		});
		buttonOpenCfile.setBounds(400, 180, 75, 28);
		panelDataSignature.add(buttonOpenCfile);
		
		JButton buttonOpenSfile = new JButton("\u6D4F\u89C8");
		buttonOpenSfile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fileChooser.showSaveDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION)
				{
					cipherfile = fileChooser.getSelectedFile();
					textFieldSignfile.setText(cipherfile.getAbsolutePath());
				}
				else {
					return;
				}
			}
		});
		buttonOpenSfile.setBounds(400, 213, 75, 28);
		panelDataSignature.add(buttonOpenSfile);
		
		JPanel paneMac = new JPanel();
		tabbedPane.addTab("Mac", null, paneMac, null);
		paneMac.setLayout(null);
		
		JButton buttonOpen = new JButton("\u6D4F\u89C8");
		buttonOpen.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				plainfile = null;
				fileChooser = new JFileChooser("C");
				int returnVal = fileChooser.showOpenDialog(null);
				if(returnVal == JFileChooser.APPROVE_OPTION)
				{
					plainfile = fileChooser.getSelectedFile();
					textFieldDataField.setText(plainfile.getAbsolutePath());
				}
				else {
					return;
				}
			}
		});
		buttonOpen.setBounds(398, 10, 64, 23);
		paneMac.add(buttonOpen);
		
		
		textFieldDataField = new JTextField();
		textFieldDataField.setColumns(10);
		textFieldDataField.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textFieldDataField.setBounds(127, 10, 261, 23);
		paneMac.add(textFieldDataField);
		
		JComboBox comboBoxDataType = new JComboBox();
		comboBoxDataType.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(comboBoxDataType.getSelectedIndex() == 1) {
					textFieldDataField.setText(null);
					buttonOpen.setVisible(false);
					textFieldDataField.setSize(335, 23);
				}
				else {
					textFieldDataField.setText(null);
					buttonOpen.setVisible(true);
					textFieldDataField.setSize(261, 23);
				}
			}
		});
		comboBoxDataType.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboBoxDataType.setModel(new DefaultComboBoxModel(new String[] {"File", "Text string"}));
		comboBoxDataType.setBounds(10, 10, 107, 23);
		paneMac.add(comboBoxDataType);

		JComboBox comboBoxKeyType = new JComboBox();
		comboBoxKeyType.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(comboBoxKeyType.getSelectedIndex() == 1){
					textFieldGPassword.setVisible(false);
				}
				else {
					textFieldGPassword.setVisible(true);
				}
			}
		});
		comboBoxKeyType.setFont(new Font("Arial Rounded MT Bold", Font.PLAIN, 12));
		comboBoxKeyType.setModel(new DefaultComboBoxModel(new String[] {"GivenKey", "GenerateKey"}));
		comboBoxKeyType.setBounds(10, 43, 109, 23);
		paneMac.add(comboBoxKeyType);
		
		textFieldGPassword = new JTextField();
		textFieldGPassword.setBounds(127, 43, 335, 21);
		paneMac.add(textFieldGPassword);
		textFieldGPassword.setColumns(10);
		
		JCheckBox checkBoxMD5 = new JCheckBox("HmacMD5");
		checkBoxMD5.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxMD5.setBounds(10, 72, 82, 23);
		paneMac.add(checkBoxMD5);
		
		textFieldMMD5 = new JTextField();
		textFieldMMD5.setEditable(false);
		textFieldMMD5.setColumns(10);
		textFieldMMD5.setBounds(127, 74, 335, 21);
		paneMac.add(textFieldMMD5);
		
		JCheckBox checkBoxSHA1 = new JCheckBox("HmacSHA1");
		checkBoxSHA1.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA1.setBounds(10, 97, 86, 23);
		paneMac.add(checkBoxSHA1);
		
		textFieldMSHA1 = new JTextField();
		textFieldMSHA1.setEditable(false);
		textFieldMSHA1.setColumns(10);
		textFieldMSHA1.setBounds(127, 98, 335, 21);
		paneMac.add(textFieldMSHA1);
		
		JCheckBox checkBoxSHA224 = new JCheckBox("HmacSHA-224");
		checkBoxSHA224.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA224.setBounds(10, 122, 109, 23);
		paneMac.add(checkBoxSHA224);
		
		textFieldMSHA224 = new JTextField();
		textFieldMSHA224.setEditable(false);
		textFieldMSHA224.setColumns(10);
		textFieldMSHA224.setBounds(127, 123, 335, 21);
		paneMac.add(textFieldMSHA224);
		
		JCheckBox checkBoxSHA256 = new JCheckBox("HmacSHA-256");
		checkBoxSHA256.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA256.setBounds(10, 148, 109, 23);
		paneMac.add(checkBoxSHA256);
		
		textFieldMSHA256 = new JTextField();
		textFieldMSHA256.setEditable(false);
		textFieldMSHA256.setColumns(10);
		textFieldMSHA256.setBounds(127, 149, 335, 21);
		paneMac.add(textFieldMSHA256);
		
		JCheckBox checkBoxSHA384 = new JCheckBox("HmacSHA-384");
		checkBoxSHA384.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA384.setBounds(10, 173, 109, 23);
		paneMac.add(checkBoxSHA384);
		
		textFieldMSHA384 = new JTextField();
		textFieldMSHA384.setEditable(false);
		textFieldMSHA384.setColumns(10);
		textFieldMSHA384.setBounds(127, 174, 335, 21);
		paneMac.add(textFieldMSHA384);
		
		JCheckBox checkBoxSHA512 = new JCheckBox("HmacSHA-512");
		checkBoxSHA512.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA512.setBounds(10, 198, 109, 23);
		paneMac.add(checkBoxSHA512);
		
		textFieldMSHA512 = new JTextField();
		textFieldMSHA512.setEditable(false);
		textFieldMSHA512.setColumns(10);
		textFieldMSHA512.setBounds(127, 199, 335, 21);
		paneMac.add(textFieldMSHA512);
		
		JCheckBox checkBoxSHA3224 = new JCheckBox("HmacSHA3-224\r\n");
		checkBoxSHA3224.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA3224.setBounds(10, 223, 109, 23);
		paneMac.add(checkBoxSHA3224);
		
		textFieldMSHA3224 = new JTextField();
		textFieldMSHA3224.setEditable(false);
		textFieldMSHA3224.setColumns(10);
		textFieldMSHA3224.setBounds(127, 224, 335, 21);
		paneMac.add(textFieldMSHA3224);
		
		JCheckBox checkBoxSHA3256 = new JCheckBox("HmacSHA3-256");
		checkBoxSHA3256.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA3256.setBounds(10, 248, 109, 23);
		paneMac.add(checkBoxSHA3256);
		
		textFieldMSHA3256 = new JTextField();
		textFieldMSHA3256.setEditable(false);
		textFieldMSHA3256.setColumns(10);
		textFieldMSHA3256.setBounds(127, 249, 335, 21);
		paneMac.add(textFieldMSHA3256);
		
		JCheckBox checkBoxSHA3384 = new JCheckBox("HmacSHA3-384");
		checkBoxSHA3384.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA3384.setBounds(10, 273, 111, 23);
		paneMac.add(checkBoxSHA3384);
		
		textFieldMSHA3384 = new JTextField();
		textFieldMSHA3384.setEditable(false);
		textFieldMSHA3384.setColumns(10);
		textFieldMSHA3384.setBounds(127, 274, 335, 21);
		paneMac.add(textFieldMSHA3384);
		
		JCheckBox checkBoxSHA3512 = new JCheckBox("HmacSHA3-512");
		checkBoxSHA3512.setFont(new Font("Bahnschrift", Font.PLAIN, 12));
		checkBoxSHA3512.setBounds(10, 298, 109, 23);
		paneMac.add(checkBoxSHA3512);
		
		textFieldMSHA3512 = new JTextField();
		textFieldMSHA3512.setEditable(false);
		textFieldMSHA3512.setColumns(10);
		textFieldMSHA3512.setBounds(127, 299, 335, 21);
		paneMac.add(textFieldMSHA3512);
		
		JCheckBox[] checkBox = {checkBoxMD5,checkBoxSHA1,checkBoxSHA224,checkBoxSHA256,checkBoxSHA384,checkBoxSHA512,checkBoxSHA3224,checkBoxSHA3256,checkBoxSHA3384,checkBoxSHA3512};
		JTextField[] textFields = {textFieldMMD5,textFieldMSHA1,textFieldMSHA224,textFieldMSHA256,textFieldMSHA384,textFieldMSHA512,textFieldMSHA3224,textFieldMSHA3256,textFieldMSHA3384,textFieldMSHA3512};
		String[] macName = {"MD5","SHA1","SHA224","SHA256","SHA384","SHA512","SHA3-224","SHA3-256","SHA3-384","SHA3-512"};
		
		JButton buttonMCulcalte = new JButton("\u8BA1\u7B97");
		buttonMCulcalte.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					if(comboBoxDataType.getSelectedIndex() == 1) {
						for(int i = 0;i < checkBox.length;i++) {
							if(checkBox[i].isSelected()) {
								byte[] keyValue = null;
								if(comboBoxKeyType.getSelectedIndex() == 0) {
									keyValue = textFieldGPassword.getText().getBytes();
								}
								else {
									KeyGenerator keyGenerator = KeyGenerator.getInstance("Hmac" + macName[i]);
									SecretKey secretKey = keyGenerator.generateKey();
									keyValue = secretKey.getEncoded();
								}
								SecretKey secretKeyMac = new SecretKeySpec(keyValue, "Hmac" + macName[i]);
								Mac mac = Mac.getInstance("Hmac" + macName[i]);
								mac.init(secretKeyMac);
								byte[] macValue = mac.doFinal(textFieldDataField.getText().getBytes());
								textFields[i].setText(Hex.toHexString(macValue));
							}
							else {
								textFields[i].setText("");
							}
						}
					}
					else {
						for(int i = 0;i < checkBox.length;i++) {
							if(checkBox[i].isSelected()) {
								FileInputStream fis = new FileInputStream(plainfile);	
								Mac mac = Mac.getInstance("Hmac" + macName[i]);
								KeyGenerator keyGenerator = KeyGenerator.getInstance("Hmac" + macName[i]);
								if(comboBoxKeyType.getSelectedIndex() == 0) {
									MessageDigest md = MessageDigest.getInstance("SHA3-512");
									String passwd = textFieldGPassword.getText();
									md.update(passwd.getBytes());
									byte[] digestValue = md.digest();				
									SecretKey secretKey = new SecretKeySpec(digestValue, "Hmac" + macName[i]);		
									mac.init(secretKey);
								}
								else {
									SecretKey secretKey = keyGenerator.generateKey();
									byte[] keyValue = secretKey.getEncoded(); 
									SecretKey secretKeyMac = new SecretKeySpec(keyValue, "Hmac" + macName[i]);						
									mac.init(secretKeyMac);
								}
								int n = -1;
								byte[] buffer = new byte[2048];
								while((n = fis.read(buffer)) != -1)
								{
									mac.update(buffer, 0, n);
								}
								byte[] macValue = mac.doFinal();
								textFields[i].setText(Hex.toHexString(macValue));
							}
							else {
								textFields[i].setText("");
							}
						}
					}
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IllegalStateException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		buttonMCulcalte.setBounds(159, 329, 76, 23);
		paneMac.add(buttonMCulcalte);
		
		JButton buttonMClear = new JButton("\u6E05\u7A7A");
		buttonMClear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for(int i = 0;i < checkBox.length;i++) {
					if(checkBox[i].isSelected()) {
						textFields[i].setText(null);
					}
				}
			}
		});
		buttonMClear.setBounds(276, 329, 76, 23);
		paneMac.add(buttonMClear);
		
		JButton buttonMClose = new JButton("\u5173\u95ED");
		buttonMClose.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		buttonMClose.setBounds(386, 330, 76, 23);
		paneMac.add(buttonMClose);
	}
}
