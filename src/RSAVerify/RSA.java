package RSAVerify;

import it.unisa.dia.gas.jpbc.Element;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import baseModel.BLS_01;
import tool.Accumulator;
import tool.Stopwatch;
public class RSA {

	public static final String HMAC_SHA1 = "HmacSHA1";

	public static List<BigInteger> ai = new  ArrayList<BigInteger>();//系数ai ;

	private RSAMeta meta=null; 

	public RSAMeta getMeta() {
		return meta;
	}
	public void setMeta(RSAMeta meta) {
		this.meta = meta;
	}

	int keySize=2048;//默认值  	

	public RSA(RSAMeta meta){
		this.meta=meta;
	}
	// 设置PK=（N，g）
	public void SetPK()
	{	
		SetN_FN(keySize);
		setG();
	}
	private void setG() {
		// TODO Auto-generated method stub
		Random r = new Random(2013);
		int b = 1 + r.nextInt(9999);
		while (gcd( (BigInteger) meta.N , b + 1) != 1 || gcd( (BigInteger) meta.N , b - 1) != 1)
		{
			b = 1 + r.nextInt(9999);
		}
		meta.G =BigInteger.valueOf( b * b );

	}
	private int gcd(BigInteger n, int i) {
		// TODO Auto-generated method stub
		BigInteger num =  BigInteger.valueOf(i);
		return (n.gcd(num)).intValue();
	}

	private void SetN_FN(int nLength)
	{
		//String[] output = new String[5]; // 用来存储密钥的e n d p q
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(nLength); // 指定密钥的长度，初始化密钥对生成器
			KeyPair kp = kpg.generateKeyPair(); // 生成密钥对
			RSAPublicKey puk = (RSAPublicKey) kp.getPublic();
			RSAPrivateCrtKey prk = (RSAPrivateCrtKey) kp.getPrivate();
            System.out.println("keysize="+prk.getPrimeP().toByteArray().length);
			BigInteger I=new BigInteger("1");
			meta.FN = (prk.getPrimeP().subtract(I)).multiply((prk.getPrimeQ().subtract(I)));
			meta.N = prk.getModulus();

			//加密后的密文  
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
		}             
	}

	public BigInteger creatDm(byte[] data){//为某块生成Dm
		BigInteger newBigData,Dm, bigData;		
		bigData=new BigInteger(data);//将这个块转换为大整数bigData		
		newBigData = bigData.mod(meta.FN); // m mod φ(n)	          
		Dm = meta.G.modPow(newBigData , meta.N);//D=g^m mod N
		return Dm;
	}
	//发出挑战，产生块的编号，r,以及gs.传递给服务器

	public void Challenge()
	{
		Random random = new Random();
		int int_max = java.lang.Integer.MAX_VALUE ;
		meta.R = 1 + random.nextInt(int_max - 1); 
		meta.S = new BigInteger(128,1,new Random());//随机数的生成
		meta.GS = meta.G.modPow(meta.S, meta.N);// gs=g^s mod N =====S在哪里设置？
	}

	public BigInteger GenProof(byte[] message,  int nums) throws Exception{//block表示块的编号

		ai = new GenerateRandom(meta).GenerateRandom128(meta.R, nums); //产生128bit的随机数 
        System.out.println("ai.length="+ai.size()+"\n"+ai);
		BigInteger bigData =new BigInteger(message);	

		bigData = ai.get(nums - 1).multiply(bigData) ;//ai*mi 	 

		BigInteger R = meta.GS.modPow(bigData, meta.N);        
		return R;

	}

	//nums 取1
	public boolean proofVerify(BigInteger Dm, BigInteger R,int nums) throws Exception
	{
		RSAMeta Meta=this.getMeta();	
		BigInteger p = Dm.modPow(ai.get(nums-1), Meta.N);//Di^ai mod N 
		BigInteger tagR = p.modPow(Meta.S, Meta.N);//R'=P^s mod N

		return tagR.equals(R);
	}

	

	public static void main (String [] args) throws Exception{
		byte[] message="abcde".getBytes();
		Accumulator acc=new Accumulator();
		for(int i=0;i<1;i++){
			Stopwatch start=new  Stopwatch();
			
			RSA rsa=new RSA(new RSAMeta());	
			rsa.SetPK();
			BigInteger Dm=rsa.creatDm(message);
			rsa.Challenge();
			BigInteger proof=rsa.GenProof(message, 1);
			assertTrue(rsa.proofVerify(Dm, proof, 1));	    
			assertFalse(rsa.proofVerify(Dm, proof.add(proof), 1));
			
			acc.addDataValue(start.elapsedTime());
		}
		System.out.println(acc.mean());

	}

}