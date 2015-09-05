/**
 * 功能描述：
 * 1.采用非对称的双线性映射
 * 2.采用带签名保护的索引哈希表
 * 3.服务器对数据标签进行累成，由服务器计算，最小化校验者的计算量
 * 4.服务器端对数据标签累成的改进版本
 * 5.批量校验
 * 6.包含对信息盲化处理
 */

package IHT;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import DetectErrors.FindErrorBlock;
import IHT.IndexHashTable.Item;
import MHT.MHTPADD_03.Chal;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.GenerateRandom;
import tool.SortAlg;
import tool.StdOut;
/**
 * 采用IndexHashTable实现的数据校验方案
 * @author MichaelSun
 * @version 2.0
 * @date  2014.12.23
 * 
 */
public class IHTPADD_02 {
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";

	//收集信息保存到文件
	public  static Map<String,String> publicInfor=new LinkedHashMap<String,String>();
	public 	static Map<String,String> doPrivate=new LinkedHashMap<String,String>();
	public  static Map<String,String> verInfor=new LinkedHashMap<String,String>();
	public  static Map<String,String> cspInfor=new LinkedHashMap<String,String>();

	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;
	private Element g2;	
	public  String fileId;			//校验者Hid需要文件名

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
	public IHTPADD_02(boolean usePBC, String curvePath) {
		this.usePBC=usePBC;
		this.curvePath=curvePath;
	}

	/**
	 * 初始化设置
	 * @param s 数据块的段数
	 */
	public void setup(){
		PairingFactory.getInstance().setUsePBCWhenPossible(usePBC);
		pairing = PairingFactory.getPairing(curvePath);
		g1 = pairing.getG1().newRandomElement().getImmutable();
		g2 = pairing.getG2().newRandomElement().getImmutable();
		
		//publicInfor.put("pairing", pairing.toString());
		publicInfor.put("g1", g1.duplicate().toString());		
		publicInfor.put("g2", g2.duplicate().toString());

	}
	/**
	 * 生成初始化密钥
	 * @return
	 */
	public Map<String, Element> keyGen(){
		Map<String, Element> keyMap = new HashMap<String, Element>(2);

		//生成密钥x
		Element x = pairing.getZr().newRandomElement().getImmutable();	
		doPrivate.put("a"+0, x.duplicate().toString());
		//生成公钥pk
		Element v = g2.duplicate().powZn(x);
		publicInfor.put("v", v.duplicate().toString());
		verInfor.put("v", v.duplicate().toString());

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

	/*//H(m1)...H(mn)——>在G中
	public Element[] allGElement(Element[]pfield){
		int length=pfield.length;
		Element[] gdata=new Element[length];
		StdOut.println("H(mi)->g：");
		for(int i=0;i<length;i++){
			gdata[i]=pairing.getG1().newElementFromHash(pfield[i].toBytes(),0,pfield[i].getLengthInBytes());
			//StdOut.println((i+1)+"block "+new String(Hex.encode(gdata[i].toBytes())));
			StdOut.print((i+1)+"block ");
		}
		StdOut.println();
		return gdata;
	}*/



	/**
	 * 获得文件元信息标签——基于分段的处理
	 * @param fileName    文件名
	 * @param blockNums   文件块数	
	 * @return            文件元信息——用于验证
	 * @throws Exception
	 */
	public byte[] fileTagGen(String fileName,int blockNums,Element[]us) throws Exception{
		Map<String,Object>sigKey=DSACoder.initKey();
		String data=fileName+String.valueOf(blockNums)+elementSCat(us).toString();
		String sigFileMeta=DSACoder.sign(data.getBytes(),DSACoder.getPrivateKey(sigKey)).toString();
		doPrivate.put("fileTag", sigFileMeta);
		cspInfor.put("fileTag", sigFileMeta);
		return (data+sigFileMeta).getBytes();
	}

	/**
	 * 生成指定s个G中元素
	 * @param ps
	 */
	public Element[] usGen(Element[] ps){//生成校验标签时减少计算开销
		int s=ps.length;
		Element []us=new Element[s];		
		for(int i=0;i<s;i++){			
			//ui=g1^ai
			us[i]=g1.duplicate().powZn(ps[i]);
			doPrivate.put("u"+(i+1), us[i].duplicate().toString());
			cspInfor.put("u"+(i+1), us[i].duplicate().toString());//云服务需要u1......us
		}
		return us;
	}
	/**
	 * 随机生成s个Zp中元素
	 * @param s
	 * @return
	 */
	public Element[] psGen(int s){
		Element [] ps=new Element[s];
		for(int i=0;i<s;i++){
			//a1,...as
			ps[i]=pairing.getZr().newRandomElement();
			doPrivate.put("a"+(i+1),ps[i].duplicate().toString());
		}
		return ps;
	}

	public Element hashKeyGen(Element[] ps,Element x){
		int s=ps.length;
		Element hashKey =pairing.getZr().newZeroElement();
		for(int i=0;i<s;i++){
			hashKey=hashKey.duplicate().add(ps[i]);
		}
		hashKey=hashKey.duplicate().add(x);
		return hashKey;
	}

	/**
	 * 校验者产生挑战的随机数
	 * @return	Zp中的随机数
	 */
	public Element rGen(){
		Element r= pairing.getZr().newRandomElement();
		verInfor.put("r", r.duplicate().toString());
		return r;
	}
	/**
	 * 生成的块标签
	 * @param blockNum 	文件块编号
	 * @param Hid		块属性信息映射到G中元素
	 * @param x			密钥
	 * @param mij		块中的段元素数组
	 * @return			文件块标签
	 */
	public Element metaGen(int blockNum,Element Hid,Element x,Element[]mij,Element []ps){
		int s=mij.length;		
		//生成文件块标签：t=(H(filename||Bi||vi||R)*(∏uj^mij))^x
		Element aggSum =pairing.getZr().newZeroElement();
		for(int i=0;i<s;i++){
			aggSum=aggSum.add(ps[i].duplicate().mulZn(mij[i]));
		}		
		Element t=(Hid.duplicate().mul(g1.duplicate().powZn(aggSum))).powZn(x);       

		return t;
	}





	/**
	 * 校验者生成挑战信息
	 * @param c   			校验块数
	 * @param allBlocks   	全部块数
	 * @param v				公钥
	 * @return				挑战信息ChallengeR
	 */
	public Map<String,Object> challengeGen(int c,int allBlocks,Element v,Element r,String fileId){
		int []ran=new int[c];
		ran=GenerateRandom.random(1,allBlocks,c); //1-allBlocks中的c个不同的数
		SortAlg.sort(ran, 0, c-1);
		Chal[]challenge=new Chal[c];		
		//生成每块对应的随机数vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
		}		
		Element R=v.duplicate().powZn(r);//!!!这里的v公钥必须duplicate
		this.fileId=fileId;	
		Map<String,Object> challengeR=new HashMap<String,Object>(2);
		challengeR.put("challenge", challenge);
		challengeR.put("R", R);	
		return challengeR;
	}

	//改进挑战的传输量：多个块号+一个生成随机数的哈希密钥k1
	public Map<String,Object>  challengeGen2(int c,int allBlocks,Element v,Element r,String fileId){
		int []blocknum=new int[c];			
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();
		BigInteger k2=pairing.getZr().newRandomElement().toBigInteger();//生成块号的种子
		blocknum=GenerateRandom.random(1,allBlocks,c,k2.longValue()); //1-allBlocks中的c个不同的数

		//k1当成hash的密钥，生成每块对应的随机数vi
		Element[]vi=randomVi(c,blocknum,k1,pairing.getZr());
		Element R=v.duplicate().powZn(r);//!!!这里的v公钥必须duplicate
		this.fileId=fileId;	
		Map<String,Object> challengeKR=new HashMap<String,Object>(2);
		challengeKR.put("vi", vi);
		challengeKR.put("blocknum", blocknum);//数据块的编号
		challengeKR.put("R", R);
		challengeKR.put("k1", k1);

		verInfor.put("blocknum",intsToString(blocknum));
		verInfor.put("R", R.toString());
		verInfor.put("vi", elementsToString(vi));
		verInfor.put("k1", k1.toString());

		return challengeKR ;
	}
	//测试对固定采样块进行多次挑战，计算时间消耗
	public Map<String,Object>  challengeGen3(int[] samplec,int start,int end,Element v,Element r,String fileId){

		int c=end-start+1;
		int [] blocknum=new int[c];
		for(int j=0;j<c;j++){
			blocknum[j]=samplec[start+j-1];
		}
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();

		//k1当成hash的密钥，生成每块对应的随机数vi
		Element[]vi=randomVi(c,blocknum,k1,pairing.getZr());
		Element R=v.duplicate().powZn(r);
		this.fileId=fileId;	
		Map<String,Object> challengeKR=new HashMap<String,Object>(2);
		challengeKR.put("vi", vi);
		challengeKR.put("blocknum", blocknum);
		challengeKR.put("R", R);
		challengeKR.put("k1", k1);

		verInfor.put("blocknum",intsToString(blocknum));
		verInfor.put("R", R.toString());
		verInfor.put("vi", elementsToString(vi));
		verInfor.put("k1", k1.toString());

		return challengeKR ;
	}


	//出错情况向采用矩阵的方式进行挑战
	public Map<String,Object>  challengeGen4(int [] blocknum,Element v,Element r,String fileId){
		int c=blocknum.length;	

		//k1当成hash的密钥，生成每块对应的随机数vi
		BigInteger k1=pairing.getZr().newRandomElement().toBigInteger();
		Element[]vi=randomVi(c,blocknum,k1,pairing.getZr());
		Element R=v.duplicate().powZn(r);//!!!这里的v公钥必须duplicate
		this.fileId=fileId;	

		//获得矩阵的行列		
		Map<String,Integer> mab=FindErrorBlock.getMatrixIndex(c);

		Map<String,Object> challengeKR=new HashMap<String,Object>(2);
		challengeKR.put("vi", vi);
		challengeKR.put("blocknum", blocknum);//数据块的编号
		challengeKR.put("R", R);
		challengeKR.put("k1", k1);
		challengeKR.put("row", mab.get("row"));
		challengeKR.put("col", mab.get("col"));

		verInfor.put("blocknum",intsToString(blocknum));
		verInfor.put("R", R.toString());
		verInfor.put("vi", elementsToString(vi));
		verInfor.put("k1", k1.toString());
		verInfor.put("row", mab.get("row").toString());
		verInfor.put("col", mab.get("col").toString());		
		return challengeKR ;
	}
	//产生c个挑战块对应的随机数
	public Element[] randomVi(int c,int[] blocknum,BigInteger k1,Field Zp){
		Element []vi=new Element[c];
		for(int i=0;i<c;i++){
			vi[i]=Zp.newElement(k1.add(BigInteger.valueOf(blocknum[i])));

		}
		return vi;
	}


	/**
	 * CSP构建数据完整性证据proof——数据标签累乘
	 * @param vi 每个挑战块对应的随机数	
	 * @param ti 每个块的元标签	
	 * @param R  挑战的时间戳
	 * @return
	 */
	public Map<String,Object> genProof(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		//这里求和时存在一个问题：每项进行模域运算，还是对求和结果进行模域运算，暂时我取前者
		int s=us.length;
		int c=vi.length;			
		Element aggreTMul=pairing.getG1().newOneElement();//块标签累成
		Element aggreDMul=pairing.getGT().newOneElement();//数据块累成
		Element aggreSum;
		//数据块的累成
		for(int k=0;k<s;k++){
			aggreSum=pairing.getZr().newZeroElement();//每次重新生成一个初始0元素
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][k]));
			}	
			//∏(e(uj,R)^MPj)
			aggreDMul=aggreDMul.mul(pairing.pairing(us[k].duplicate(),R.duplicate()).powZn(aggreSum));
		}
		//数据标签的累乘
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}
		//全局变量proof保存信息
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);		
		return proof;


	}

	//加速证据生成∏(e(uj,R)^MPj)->e(∏uj^MPj,R)	
	public Map<String,Object> genProof2(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		//这里求和时存在一个问题：每项进行模域运算，还是对求和结果进行模域运算，暂时我取前者
		int s=us.length;
		int c=vi.length;			

		Element aggreTMul=pairing.getG1().newOneElement();//块标签累成
		Element aggreDMulTemp=pairing.getG1().newOneElement();//数据块累成
		Element aggreSum;
		//数据块的累成
		for(int k=0;k<s;k++){
			aggreSum=pairing.getZr().newZeroElement();//每次重新生成一个初始0元素
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][k]));
			}
			//∏uj^MPj
			aggreDMulTemp=aggreDMulTemp.mul(us[k].duplicate().powZn(aggreSum));
		}
		//e(∏uj^MPj,R)
		Element aggreDMul=pairing.pairing(aggreDMulTemp, R.duplicate());
		//数据标签的累乘
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//全局变量proof保存信息
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);	
		return proof;

	}

	//加入对数据进行盲化处理
	public Map<String,Object> genProof3(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		int s=us.length;
		int c=vi.length;
		Element [] a=new Element[s];//CSP对信息盲化保存的随机秘密值
		Element [] b=new Element[s];//存放ui^ai
		Element aggreTMul=pairing.getG1().newOneElement();//块标签累成
		Element aggreDMulTemp=pairing.getG1().newOneElement();//数据块累成
		Element aggreRanMulTemp=pairing.getG1().newOneElement();//盲化处理部分的累乘
		Element aggreSum;
		//数据块的累成
		for(int j=0;j<s;j++){
			//盲化信息处理：aj<-Zp;bj<-usj^aj;h(bj)->Zp
			a[j]=pairing.getZr().newRandomElement();
			b[j]=us[j].duplicate().powZn(a[j]);
			//Element hb=pairing.getZr().newElementFromBytes(b[j].toBytes());//需要用hash映射？
			Element hb=pairing.getZr().newElementFromHash(b[j].toBytes(),0,b[j].toBytes().length);//用hash映射
			Element ahb=a[j].mul(hb);
			//∏bj^h(bj)
			aggreRanMulTemp=aggreRanMulTemp.mul(b[j].duplicate().powZn(hb));
			aggreSum=pairing.getZr().newZeroElement();//每次重新生成一个初始0元素
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][j]));
			}			
			aggreSum=aggreSum.add(ahb);
			//∏uj^MPj
			aggreDMulTemp=aggreDMulTemp.mul(us[j].duplicate().powZn(aggreSum));
		}
		//e(∏uj^MPj,R)
		Element aggreDMul=pairing.pairing(aggreDMulTemp, R.duplicate());
		Element aggreRanMul=pairing.pairing(aggreRanMulTemp, R.duplicate());

		//数据标签的累乘
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//全局变量proof保存信息
		Map<String,Object> proof=new HashMap<String,Object>(4);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);
		proof.put("aggreRanMul",aggreRanMul);
		return proof;

	}
	//盲化处理2
	public Map<String,Object> genProof4(Element[] vi,Element[][] mij,Element[] ti,Element R,Element[]us){
		int s=us.length;
		int c=vi.length;
		Element a=pairing.getZr().newRandomElement();;//CSP对信息盲化保存的随机秘密值
		Element b=us[new Random().nextInt(s)].duplicate().powZn(a);//存放ui^a
		Element aggreTMul=pairing.getG1().newOneElement();//块标签累成
		Element aggreDMulTemp=pairing.getG1().newOneElement();//数据块累成
		Element aggreSum;
		//数据块的累成
		for(int j=0;j<s;j++){
			aggreSum=pairing.getZr().newZeroElement();//每次重新生成一个初始0元素
			for(int i=0;i<c;i++){				
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][j]));
			}			
			//∏uj^MPj
			aggreDMulTemp=aggreDMulTemp.mul(us[j].duplicate().powZn(aggreSum));
		}
		//e((∏uj^MPj)*b,R)
		Element aggreDMul=pairing.pairing(aggreDMulTemp.mul(b), R.duplicate());
		//e(b,R)
		Element aggreRanMul=pairing.pairing(b, R.duplicate());

		//数据标签的累乘
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//全局变量proof保存信息
		Map<String,Object> proof=new HashMap<String,Object>(4);
		proof.put("aggreDMul", aggreDMul);
		proof.put("aggreTMul", aggreTMul);
		proof.put("aggreRanMul",aggreRanMul);
		return proof;

	}

  
	//批量校验
	public Map<String,Object> genBathProof(List<Map<String,Object>>kchallengeRs,List<Element[][]> kmij,List<Element[]> kti,List<Element[]>kus,int s){
		int K=kchallengeRs.size();						
		Element kaggreTMul=pairing.getG1().newOneElement();	
		Element kaggreDMul=pairing.getGT().newOneElement();//k个数据块累成

		for(int k=0;k<K;k++){
			Map<String,Object>challengeRs=kchallengeRs.get(k);
			Chal []challenge=(Chal[])challengeRs.get("challenge");
			int CBCounts=challenge.length;
			Element R=(Element)challengeRs.get("R");
			Element[][] mij=kmij.get(k);	//第k个挑战的段集合
			Element[]us=kus.get(k);			//第k个挑战的标签随机数集合
			Element aggreDMulTemp=pairing.getG1().newOneElement();//数据块累成

			//数据块的累成
			for(int j=0;j<s;j++){
				Element aggreSum=pairing.getZr().newZeroElement();//每次重新生成一个初始0元素
				for(int i=0;i<CBCounts;i++){				
					//sum(vi*mij)
					aggreSum=aggreSum.add(challenge[i].random.duplicate().mulZn(mij[i][j]));
				}
				//∏uj^MPj
				aggreDMulTemp=aggreDMulTemp.mul(us[j].duplicate().powZn(aggreSum));
			}
			//e(∏uj^MPj,R)
			kaggreDMul=kaggreDMul.mul(pairing.pairing(aggreDMulTemp, R.duplicate()));

			//数据标签的累乘
			Element aggreTMul=pairing.getG1().newOneElement();//块标签累成
			Element[]ti=kti.get(k);			//第k个挑战的块标签的集合
			for(int i=0;i<CBCounts;i++){			
				//mul(ti^vi)
				aggreTMul=aggreTMul.mul(ti[i].duplicate().powZn(challenge[i].random));
			}
			kaggreTMul=kaggreTMul.mul(aggreTMul);
		}
		//全局变量proof保存信息
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("kaggreDMul", kaggreDMul);
		proof.put("kaggreTMul", kaggreTMul);	
		return proof;

	}

	/**
	 * 根据CSP发来的Proof,校验者验证Proof是否正确	
	 * @param v 公钥	
	 * @return  true或false
	 */
	public boolean proofVerify(Element v,Element r,Map<String,Object> challengeR ,Map<String,Object> proof,String fileId){
		Chal[] challenge=(Chal[])challengeR.get("challenge");		
		Element aggreTMul=(Element)proof.get("aggreTMul");
		Element aggreDMul=(Element)(proof.get("aggreDMul"));
		Item[] id=(Item[])proof.get("id");//挑战块的索引哈希条目集合
		Element aggreRanMul=(Element)proof.get("aggreRanMul");
		//Hchal=h(Idi)^(r*vi)
		int c=id.length;		
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
			Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
			Element tmp=Hid.powZn(r.duplicate().mulZn(challenge[i].random));
			aggreBlock=aggreBlock.mul(tmp);
		}	
		//e(Hchal,v)	
		Element temp1 =pairing.pairing(aggreBlock,v);	
		//e(Tp,g2^r)
		Element temp2 = pairing.pairing(aggreTMul, g2.powZn(r));
		return (aggreDMul.mul(temp1)).equals(aggreRanMul.mul(temp2))? true :false;//盲化信息处理

	}

	//挑战：（Q,k1,R)。对证据进行验证
	public boolean proofVerify2(Element v,Element r,Map<String,Object> challengeKR ,Map<String,Object> proof,String fileId){

		//int[] blocknum=(int [])challengeKR.get("blocknum");
		Element[] vi=(Element[])challengeKR.get("vi");	
		Element aggreTMul=(Element)proof.get("aggreTMul");
		Element aggreDMul=(Element)(proof.get("aggreDMul"));
		Item[] id=(Item[])proof.get("id");//挑战块的索引哈希条目集合
		Element aggreRanMul=(Element)proof.get("aggreRanMul");

		//Hchal=h(Idi)^(r*vi)
		int c=id.length;		
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
			Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
			Element tmp=Hid.powZn(r.duplicate().mulZn(vi[i]));
			aggreBlock=aggreBlock.mul(tmp);
		}

		//e(Hchal,v)	
		Element temp1 =pairing.pairing(aggreBlock,v);

		//e(Tp,g2^r)
		Element temp2 = pairing.pairing(aggreTMul, g2.powZn(r));
		return (aggreDMul.mul(temp1)).equals(aggreRanMul.mul(temp2))? true :false;//盲化信息处理

	}


	public boolean proofBathVerify(Element[] kv,Element r,List<Map<String,Object>> kchallengeRs ,Map<String,Object> proof,String fileId){//暂且考虑所有的fileId相同

		int K =kchallengeRs.size();
		Element kaggreTMul=(Element)proof.get("kaggreTMul");
		Element kaggreDMul=(Element)(proof.get("kaggreDMul"));
		Element keaggreMul=pairing.getGT().newOneElement();

		for(int k=0;k<K;k++){
			Chal[] challenge=(Chal[])kchallengeRs.get(k).get("challenge");
			Item[] id=((List<Item[]>)proof.get("kid")).get(k);//第k个挑战块的索引哈希条目集合
			int CBCounts=challenge.length;		
			Element aggreBlock=pairing.getG1().newOneElement();

			//Hchal=h(Idi)^(r*vi)
			for(int i=0;i<CBCounts;i++){
				byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
				Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
				Element tmp=Hid.powZn(r.duplicate().mulZn(challenge[i].random));
				aggreBlock=aggreBlock.mul(tmp);
			}
			//∏e(Hchal,v)	
			keaggreMul=keaggreMul.mul(pairing.pairing(aggreBlock,kv[k]));
		}	

		//e(kTp,g2^r)
		Element temp2 = pairing.pairing(kaggreTMul, g2.powZn(r));
		return (kaggreDMul.mul(keaggreMul)).equals(temp2)? true :false;

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

	//将Element[]数组转换成格式化的字符串以便方便输出到文件
	public static String elementsToString(Element[] e){
		int len=e.length;
		String result=e[0].duplicate().toBigInteger().toString();
		for(int i=1;i<len-1;i++)
			result+=" "+e[i].duplicate().toBigInteger().toString();
		return result;
	}

	public static String intsToString(int [] a){
		int len=a.length;
		String result=Integer.toString(a[0]);
		for(int i=1;i<len;i++){
			result+=" "+Integer.toString(a[i]);
		}
		return result;

	}

	

	public Pairing getPairing() {
		return pairing;
	}	




}
