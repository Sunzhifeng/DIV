package RSAVerify;



import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class GenerateRandom {
	private RSAMeta Meta;
	public static List<BigInteger> ai = new  ArrayList<BigInteger>();//ϵ��ai ;
	private static final byte[] keybytes = new byte[] { (byte) 0xfc, (byte) 0x4f, (byte) 0xbe, (byte) 0x23,
		(byte) 0x59, (byte) 0xf2, (byte) 0x42, (byte) 0x37, (byte) 0x4c, (byte) 0x80, (byte) 0x44, (byte) 0x31,
		(byte) 0x20, (byte) 0xda, (byte) 0x20, (byte) 0x0c };
	
	private static final String HMAC_SHA1 = "HmacSHA1";	
    public GenerateRandom(RSAMeta meta){
		this.Meta=meta;

	}
	public RSAMeta getMeta() {
		return Meta;
	}
	

	public String GenProof_block(byte[] message,  int nums) throws Exception{//block��ʾ��ı��

		ai = this.GenerateRandom128(Meta.R, nums); //����128bit������� 

		BigInteger bigData =new BigInteger(message);	

		bigData = ai.get(nums - 1).multiply(bigData) ;//ai*mi 	 

		BigInteger r = Meta.GS.modPow(bigData, Meta.N);        
		return r.toString();
		
	}
	
	public List<BigInteger> GenerateRandom128(int r, int num) throws InvalidKeyException, NoSuchAlgorithmException
	{
		List<BigInteger> list = new  ArrayList<BigInteger>();
		Random ran = new Random(r);            
		SecretKeySpec signingKey = new SecretKeySpec(keybytes, HMAC_SHA1);     
		Mac mac = Mac.getInstance(HMAC_SHA1);     
		mac.init(signingKey);     
		for (int i = 0; i < num; i++)
		{
			// ����������ͬ��Random�������ɵ������������һ���ġ�
			int int_max = java.lang.Integer.MAX_VALUE ;     	
			String data = String.valueOf(ran.nextInt(int_max - 1));         
			byte[] hashValue = mac.doFinal(data.getBytes()); 			
			list.add((new BigInteger(hashValue)).abs());
		}
		return list;
	}

	
}
