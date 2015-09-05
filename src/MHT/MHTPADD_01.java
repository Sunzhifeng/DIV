/**
 * 功能描述：
 * 1.基于块的校验
 * 2.批处理校验
 * 	
 */

package MHT;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.StdOut;
/**
 * 基于MHTPADD的数据完整性校验计划
 * @author MichaelSun
 * @version 1.1
 * @date 2014.12.24
 */
public class MHTPADD_01 {	
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g;	

	/**
	 * 挑战信息的内部类
	 */
	public  static class Chal{
		int num; //块的逻辑编号
		Element random;//相应的随机数
		public Chal(int num,Element random){
			this.num=num;
			this.random=random;
		}

	}
	
	/**
	 * 初始化校验参数
	 * @param usePBC
	 * @param curvePath
	 */
	public MHTPADD_01(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}

	/**
	 * 初始化设置
	 */
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g = pairing.getG1().newRandomElement().getImmutable();
	}
	
	/**
	 * 用于产生标签的随机值u
	 * @return
	 */
	public Element genRandomU(){
		return pairing.getG1().newRandomElement();
	}
	
	/**
	 * 生成初始化密钥
	 * @return
	 */
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);

		//生成密钥x
		Element x = pairing.getZr().newRandomElement().getImmutable();	
		//生成公钥pk
		Element v = g.duplicate().powZn(x); 
		keyMap.put(SECRETKEY, x);
		keyMap.put(PUBLICKEY, v);
		return keyMap;

	}
	
	/**
	 * 生成签名密钥：DSA
	 * 数字签名算法：SHA1withDSA
	 * @return
	 */
	public static Map<String, Object> sigKeyGen()throws Exception{
		return DSACoder.initKey();	
	}

	/**
	 * 将某块映射到Zp中的大整数：mi->Zp
	 * @param blockData    数据块的源数据
	 * @return  		   Zp中的大整数
	 */
	public Element preProcessFileBolck(byte[] blockData){
		Element m=pairing.getZr().newElementFromBytes(blockData);		
		return m;
	}

	/**
	 * 	将所有数据块转换成Zp中的大整数
	 * @param data  预处理的数据
	 * @return	   	 处理结果集		
	 */
	public Element[] allFieldElement(BigInteger[] data){//每个块对应一个大整数
		int n=data.length;
		Element[] pfield=new Element[n];
		for(int i=0;i<n;i++){
			pfield[i]=preProcessFileBolck(data[i].toByteArray());

		}
		return pfield;
	}

	/**
	 * 将Zp中数据块映射到群G中：H(m1)...H(mn)->G
	 * @param pfield
	 * @return
	 */
	public Element[] allGElement(Element[]pfield){
		int length=pfield.length;
		Element[] gdata=new Element[length];		
		for(int i=0;i<length;i++){
			gdata[i]=pairing.getG1().newElementFromHash(pfield[i].toBytes(),0,pfield[i].getLengthInBytes());
			//StdOut.println((i+1)+"block "+new String(Hex.encode(gdata[i].toBytes())));
			//StdOut.print((i+1)+"block ");
		}
		StdOut.println();
		return gdata;
	}
	
	/**
	 * 获得文件元信息标签
	 * @param fileName    文件名
	 * @param blockNums   文件块数
	 * @param u			     用于计算标签的随机值	
	 * @return            文件元信息——用于验证
	 * 
	 */
	public byte[] fileTagGen(String fileName,int blockNums,Element u) throws Exception{
		Map<String,Object>sigKey=DSACoder.initKey();
		String data=fileName+String.valueOf(blockNums)+u.toString();
		//DSA对整个文件的元信息签名
		String sigFileMeta=DSACoder.sign(data.getBytes(),DSACoder.getPrivateKey(sigKey)).toString();
		return (data+sigFileMeta).getBytes();
	}

	/**
	 * 为每个数据块生成数据标签t
	 * @param blockNum		文件块编号
	 * @param mi	 		块数据
	 * @param Hmi			mi映射到G中
	 * @param x				密钥
	 * @param u				秘密随机数
	 * @return				数据标签值
	 */
	public Element metaGen(int blockNum,Element mi,Element Hmi,Element x,Element u){
		//生成文件块标签：t=(H(m)*u^m)^x		
		Element t=(Hmi.duplicate().mul(u.duplicate().powZn(mi))).powZn(x);       
		return t;
	}

	/**
	 * 对MHT的Root进行签名
	 * @param R
	 * @param x
	 * @return
	 */
	public Element sigRoot(byte[]R ,Element x){	
		//sig(H(R))<-(H(R))^x
		Element sigR=pairing.getG1().newElementFromHash(R,0,R.length).powZn(x);
		return sigR;		
	}

	/**
	 * 获得MHT的Root的值
	 * @param blocks  H(mi)块数组
	 * @param n	      块数
	 * @return     MHT根的值
	 * @throws Exception
	 */
	public byte[] getMHTRoot(Element[] blocks,int n) throws Exception{
		return new MerkleHashTree(blocks).createMHT();
	}

	/**
	 * 校验者生成挑战信息，存放到全局变量challenge中
	 * @param c   			校验块数
	 * @param allBlocks   	全部块数
	 * return 				挑战集合
	 */
	public Chal[] challengeGen(int c,int allBlocks){
		int []ran=new int[c];
		ran=random(1,allBlocks,c); //1-allBlocks中的c个不同的数
		Chal[] challenge=new Chal[c];		
		//生成每块对应的随机数vi
		for(int i=0;i<c;i++){
			//StdOut.println(ran[i]);
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
			//StdOut.println("ChanllengeNum: "+challenge[i].num);
		}
		return challenge;
	}
	//改进挑战的传输量：多个块号+一个随机数的种子k1
	public Chal[] challengeGen2(int c,int allBlocks){
		int []ran=new int[c];		
		Chal[] challenge=new Chal[c];	
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();
		BigInteger k2=pairing.getZr().newRandomElement().toBigInteger();
		ran=random(1,allBlocks,c,k2.longValue()); //1-allBlocks中的c个不同的数
		//k1当成种子，生成每块对应的随机数vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newElement(k1.add(BigInteger.valueOf(ran[i]))));
			//StdOut.println("ChanllengeNum: "+challenge[i].num);
		}
		return challenge;
	}
	/**
	 * 生成指定范围内的多个无重复的随机数
	 * @param start	最小值
	 * @param end	最大值
	 * @param len	个数
	 * @return
	 */
	public  int[] random(int start,int end,int len){
		int [] rst=new int[len];
		Arrays.fill(rst,start-1);
		Random r=new Random();
		for (int i = 0; i < rst.length; ) {
			int ran=r.nextInt(end-start+1)+start;
			if(!isDup(rst, ran)){
				rst[i++]=ran;
			}

		}
		return rst;
	}

	public  int[] random(int start,int end,int len,long seek){
		int [] rst=new int[len];
		Arrays.fill(rst,start-1);
		Random r=new Random(seek);
		for (int i = 0; i < rst.length; ) {
			int ran=r.nextInt(end-start+1)+start;
			if(!isDup(rst, ran)){
				rst[i++]=ran;
				System.out.println("num:"+ran);
			}
		
		}
		return rst;
	}
	/**
	 * 是否存在重复的随机数
	 * @param random   以生成的随机数
	 * @param ran	       新生成的随机数
	 * @return
	 */
	boolean  isDup(int []random,int ran){
		for (int i = 0; i < random.length; i++) {
			if(random[i]==ran)
				return true;//ran是否在random数组中
		}
		return false;
	}


	/**
	 * CSP构建数据完整性证据proof——数据累加和标签累成信息
	 * @param vi 每个挑战块对应的随机数
	 * @param mi 每个块元素pfield
	 * @param ti 每个块的元标签	
	 * @return	证据的集合
	 */
	public Map<String,Object> genProof(Element[] vi,Element[] mi,Element[] ti){		
		int c=vi.length;
		Element aggreSum=pairing.getZr().newZeroElement();
		Element aggreMul=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			//sum(vi*mi)
			aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mi[i]));
			//mul(ti^vi)
			aggreMul=aggreMul.mul(ti[i].duplicate().powZn(vi[i]));
		}
		
		Map<String,Object>proof=new HashMap<String,Object>(5);	    
		proof.put("aggreSum", aggreSum);
		proof.put("aggreMul", aggreMul);		
		return proof;
	}

	/**
	 * CSP构建批校验证据proof——数据累加和标签累成信息
	 * @param vki 每个挑战块对应的随机数(可以考虑，将随机数由服务器端生成，减少数据传输量）
	 * @param mki k个用户要检查的数据块
	 * @param tki k个用户数据对应的元标签	 
	 * @return
	 */
	public Map<String,Object> genBathProof(List<Chal[]> challenges,List<Element[]> kmi,List<Element[]> kti){
		int K=challenges.size();
		Element [] kaggreSum=new Element[K];		
		Element kaggreMul=pairing.getG1().newOneElement();
		for(int k=0;k<K;k++){
			Element aggreSum=pairing.getZr().newZeroElement();
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//第k个挑战的块数量
			Element[] mi=(Element[])kmi.get(k);
			Element[] ti=kti.get(k);
			for(int i=0;i<CBCounts;i++){				
				//sum(vi*mki),k=1...K
				aggreSum=aggreSum.add((chal[i].random.duplicate()).mulZn(mi[i]));
				//mul(tki^vi),k=1...K
				kaggreMul=kaggreMul.mul(ti[i].duplicate().powZn(chal[i].random));

			}
			kaggreSum[k]=aggreSum;
		}		
		Map<String,Object>proof=new HashMap<String,Object>(5);	    
		proof.put("kaggreSum", kaggreSum);
		proof.put("kaggreMul", kaggreMul);				
		return proof;
	}
	/**
	 * 校验者验证proof是否正确
	 * @param R MHT的Root值——应该由挑战块的哈希及其辅助索引计算出R
	 * @param v 用户公钥
	 * @param sigHashRoot 签名过的MHT的H(R)
	 * @return true或false
	 */
	public boolean proofVerify(byte[]R,Element v,Element u,Chal[] chal,Map<String,Object> proof){

		//R<-genRoot(Element[] HashM,Qi)
		Element hashR=pairing.getG1().newElementFromHash(R, 0, R.length);
		Element sigHashRoot=(Element)proof.get("sigHashRoot");
		Element temp1 = pairing.pairing(sigHashRoot, g);
		Element temp2 = pairing.pairing(hashR, v);			
		Element aggreMul=(Element)proof.get("aggreMul");
		Element aggreSum=(Element)proof.get("aggreSum");
		Element[] Hmi=(Element[])proof.get("Hmi");

		//h(mi)^vi
		int c=Hmi.length;
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){			
			Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
			aggreBlock=aggreBlock.duplicate().mul(tmp);
		}

		//u^u
		Element u_=u.duplicate().powZn(aggreSum);
		Element l=aggreBlock.duplicate().mul(u_);	    
		Element temp3 =pairing.pairing(aggreMul, g);		
		Element temp4 = pairing.pairing(l, v);	

		return (temp1.equals(temp2)&&temp3.equals(temp4))? true :false;

	}
	//批量验证证据,可以考虑累成K个sigHashRoot以减少传输量

	/**
	 * 批量验证K个用户的完整性证据
	 * @param challenges k个挑战的集合
	 * @param kRoot	  k个MHT树根值
	 * @param kv	  k个公钥
	 * @param ku	  k个用户生成标签的秘密值 
	 * @param proof		证据
	 * @return
	 */
	public boolean proofBathVerify(List<Chal[]>challenges,BigInteger []kRoot,Element[] kv,Element[] ku,Map<String,Object>proof){
		Element[] ksigHashRoot=(Element[])proof.get("ksigHashRoot");
		List<Element[]>kHmi=(List<Element[]>)proof.get("kHmi");
		Element kaggreMul=(Element)proof.get("kaggreMul");
		Element[] kaggreSum=(Element[])proof.get("kaggreSum");

		//验证K个MHT的R
		//boolean MHTR=true;
		int K=kv.length;
		Element []kHashR=new Element[K];//保存临时计算的H(R)
		for(int k=0;k<K;k++){
			byte[] data=kRoot[k].toByteArray();
			Element hashR=pairing.getG1().newElementFromHash(data, 0, data.length);
			kHashR[k]=hashR.duplicate();
			Element temp1 = pairing.pairing(ksigHashRoot[k], g);
			Element temp2 = pairing.pairing(hashR, kv[k]);	
			if(!temp1.equals(temp2)){
				StdOut.println("MHT_Root验证出错！");
				//MHTR=false;
				return false;
			}
		}


		Element agg=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			Element aggreBlock=pairing.getG1().newOneElement();
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//第k个挑战的块数量
			Element[] Hmi=kHmi.get(k);
			//H(mki)^vi
			for(int i=0;i<CBCounts;i++){			
				Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
				aggreBlock=aggreBlock.duplicate().mul(tmp);
			}

			//u^u
			Element u_=ku[k].duplicate().powZn(kaggreSum[k]);
			Element l=aggreBlock.duplicate().mul(u_);		
			agg=agg.mul(pairing.pairing(l, kv[k]));	
		}
		Element temp3 =pairing.pairing(kaggreMul, g);		
		return temp3.equals(agg)? true :false;

	}
	//对根签名进行累成
	public boolean proofBathVerify2(List<Chal[]>challenges,BigInteger []kRoot,Element[] kv,Element[] ku,Map<String,Object>proof){
		Element ksigHashRootAggre=(Element)proof.get("ksigHashRootAggre");
		List<Element[]>kHmi=(List<Element[]>)proof.get("kHmi");
		Element kaggreMul=(Element)proof.get("kaggreMul");
		Element[] kaggreSum=(Element[])proof.get("kaggreSum");

		//验证K个MHT的R
		int K=kv.length;
		//Element []kHashR=new Element[K];//保存临时计算的H(R)
		Element temp2=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			byte[] data=kRoot[k].toByteArray();
			Element hashR=pairing.getG1().newElementFromHash(data, 0, data.length);
			temp2=temp2.mul(pairing.pairing(hashR, kv[k]));	
		}
		Element temp1=pairing.pairing(ksigHashRootAggre, g);
		
		//验证数据
		Element temp4=pairing.getGT().newOneElement();
		for(int k=0;k<K;k++){
			Element aggreBlock=pairing.getG1().newOneElement();
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//第k个挑战的块数量
			Element[] Hmi=kHmi.get(k);
			//H(mki)^vi
			for(int i=0;i<CBCounts;i++){			
				Element tmp=Hmi[i].duplicate().powZn(chal[i].random);
				aggreBlock=aggreBlock.duplicate().mul(tmp);
			}

			//u^u
			Element u_=ku[k].duplicate().powZn(kaggreSum[k]);
			Element l=aggreBlock.duplicate().mul(u_);		
			temp4=temp4.mul(pairing.pairing(l, kv[k]));	
		}
		Element temp3 =pairing.pairing(kaggreMul, g);		
		return temp1.equals(temp2)&&temp3.equals(temp4)? true :false;

	}


	/**
	 * 多个元素的连接操作 
	 * @param us
	 * @return
	 */
	public byte[] elementSCat(Element[]us){//这里和字符串的连接有区别吗？？
		int s=us.length;
		byte[] result=us[0].toBytes();

		for(int i=1;i<s;i++){
			result=arraycat(result,us[i].toBytes());
		}
		return result;
	}
	/**
	 * 连接两字符数组
	 * @param buf1	数组1
	 * @param buf2	数组2
	 * @return		两个数组连接结果
	 */
	public byte[] arraycat(byte[] buf1,byte[] buf2)
	{
		byte[] bufret=null;
		int len1=0;
		int len2=0;
		if(buf1!=null)
			len1=buf1.length;
		if(buf2!=null)
			len2=buf2.length;
		if(len1+len2>0)
			bufret=new byte[len1+len2];
		if(len1>0)
			System.arraycopy(buf1,0,bufret,0,len1);
		if(len2>0)
			System.arraycopy(buf2,0,bufret,len1,len2);
		return bufret;
	}

	public Pairing getPairing() {
		return pairing;
	}	



}
