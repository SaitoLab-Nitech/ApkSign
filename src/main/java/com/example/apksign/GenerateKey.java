package com.example.apksign;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Locale;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509v1CertificateBuilder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;


public class GenerateKey {
	
	private static String issuerName;
	private static X500Name issuer;
	private static BigInteger serial;
	private static Date notBefore;
	private static Date notAfter;
	private static X500Name subject;
	
	private static final long VALIDITY_PERIOD = 1000000L;
	private static final String storeType = "PKCS8";
    private static final String SIGNATURE_ALGORITHM = "SHA1WithRSAEncryption"; 
    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME; 
	
	public static void main(String args[]) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, KeyStoreException, SignatureException, IOException {
		/**
		 *  How to generate key.
		 *  First, you set CN for generating X509 certificate.
		 *  Next, you call generateKey() function for generating RSA keypair and X509 certificate.
		 *  The generateKey() function create RSA keypair and X509 certificate, and export RSA private key.
		 *  You have to save the x509 certificate.
		 *  
		 *  How to sign apk.
		 *  If you know SignApk.java, you can sign apk with X509 certificate as same as you use SignApk.java.
		 *  If you have not use SignApk.java, I show the example how to sign apk below.
		 *  About SignApk.signapk() function's arguments.
		 *  First argument is x509 certificate file path.
		 *  Second argument is RSA private key file path.
		 *  Third argument is unsigned apk file.
		 *  Last argument is apk file name which is signed. 
		 */
		GenerateKey genkey = new GenerateKey();
		genkey.setX509attribute("test","hoge", "Nagoya", "Aichi", "JP");
		X509Certificate x509 = genkey.generateKey("testkey.pk8");
		// if you run this library outside of Android , you can use certToString method.
		// But if you run the library on Android, you have to implement method which convert a certificate.
		// I implement that method in MainActivity.java of ApkSignatureSample application. Please look the code, if you want to use this library on Android.
		writeFile(certToString(x509).getBytes(), "testkey.x509.pem");
		
		// how to sign Apk
		String[] arg = new String[]{"testkey.x509.pem","testkey.pk8","csptest.apk","cspcert.apk"};
		SignApk.signapk(arg);
	}	
	
	
	public X509Certificate generateKey(String pk8FilePath) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, KeyStoreException, IOException, InvalidKeyException, SignatureException{
		Security.addProvider(new BouncyCastleProvider());
		KeyPair keypair = generateRSAKeyPair();
		PublicKey publicKey = keypair.getPublic();
		X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(new Random().nextInt()),new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis()+VALIDITY_PERIOD), subject, publicKey);
		X509Certificate cert = signCertificate(generator, keypair.getPrivate());
		cert.checkValidity(new Date());
		cert.verify(publicKey);
	
		
		// write pk8 rsa private key
		writeFile(keypair.getPrivate().getEncoded(),pk8FilePath);
		
		// write x509 certificate
		//writeFile(certToString(cert).getBytes(), "testkey.x509.pem");
		return cert;
		
	}
	
	
	public void setX509attribute(String name, String organization, String location, String station, String country){
		issuerName = "CN= "+name
				+", O= "+organization
				+", L= "+location
				+", ST= "+station
				+", C= "+country;
		issuer = new X500Name(issuerName);
		subject = issuer;
	}
	
	private static void writeFile(byte[] bytecode, String filename) throws IOException{
		File file = new File(filename);
		FileOutputStream fos = new FileOutputStream(file);
		fos.write(bytecode);
		fos.flush();
		fos.close();
	}
	
	private static String certToString(X509Certificate cert) {
	    StringWriter sw = new StringWriter();
	    try {
	        sw.write("-----BEGIN CERTIFICATE-----\n");
	        sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
	        sw.write("\n-----END CERTIFICATE-----\n");
	    } catch (CertificateEncodingException e) {
	        e.printStackTrace();
	    }
	    return sw.toString();
	}
	
	
	private static X509Certificate signCertificate( 
            X509v3CertificateBuilder certificateBuilder, 
            PrivateKey signedWithPrivateKey) throws OperatorCreationException, 
            CertificateException { 
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM) 
                .setProvider(PROVIDER_NAME).build(signedWithPrivateKey); 
        X509Certificate cert = new JcaX509CertificateConverter().setProvider( 
                PROVIDER_NAME).getCertificate(certificateBuilder.build(signer)); 
        return cert; 
    } 



	private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException{
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA"/*,"BC"*/);
		keygen.initialize(2048);
		
		KeyPair keyPair = keygen.generateKeyPair();
		return keyPair;
	}
	
	
	

}
