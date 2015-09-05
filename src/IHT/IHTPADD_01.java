/**
 * 功能描述：
 * 1.非对称双线性映射
 * 2.采用索引哈希表——带签名保护
 */

package IHT;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import IHT.IndexHashTable.Item;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sigAlg.DSACoder;
import tool.GenerateRandom;
import tool.StdOut;
/**
 * 采用IndexHashTable实现的数据校验方案
 * @author MichaelSun
 * @version 1.0
 * @date 2014.12.23
 */
public class IHTPADD_01 {
	public static final String PUBLICKEY="pubicKey";
	public static final String SECRETKEY="secretKey";
	protected String curvePath;
	protected boolean usePBC;
	protected Pairing pairing;
	private Element g1;	
	private Element g2;	
	public  String fileId;

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
	public IHTPADD_01(boolean usePBC, String curvePath) {
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
		g2= pairing.getG2().newRandomElement().getImmutable();		
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
		Element v = g2.duplicate().powZn(x); 
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

		return (data+sigFileMeta).getBytes();
	}

	/**
	 * 为文件构建索引哈希表
	 * @param fileID	文件表示
	 * @param blockNums	文件所包含的块数
	 * @param x			用户的私钥——对IHT的表项进行签名保护，这里也可考虑采用标准数字签名DSA
	 * @return
	 */
	public Item[] genIHT(String fileID,int blockNums,Element x){
		IndexHashTable ihtable=new IndexHashTable(fileID,blockNums);
		//ihtable.createIHT(pairing.getZr(),x , pairing.getG1());		
		return ihtable.createIHT(pairing.getZr(),x , pairing.getG1());		

	}

	/**
	 * 随机生成s个G中元素
	 * @param ps	s个随机Zp中元素
	 */
	public Element[] usGen(Element[]ps){
		int s=ps.length ;
		Element []us=new Element[s];	
		for(int i=0;i<s;i++){			
			//ui=g^ai
			us[i]=g1.powZn(ps[i]);	
		}
		return us;
	}

	public Element[] psGen(int s){
		Element[]ps=new Element[s];
		for(int i=0;i<s;i++){
			//a1,...as
			ps[i]=pairing.getZr().newRandomElement();
		}
		return ps;
	}
	/**
	 * 将IDi映射到G中
	 * @param item IHT中的一条表项
	 * @return 
	 */
/*	public Element genHid(Item item){
		return pairing.getG1().newElementFromBytes(item.getContact().getBytes());

	}*/

	/**
	 * 生成的块标签
	 * @param blockNum 	文件块编号
	 * @param Hid		块属性信息映射到G中元素
	 * @param x			密钥
	 * @param mij		块中的段元素数组
	 * @return			文件块标签
	 */
	public Element metaGen(int blockNum,Element Hid,Element x,Element[]mij,Element[]ps){
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
	 * 校验者生成挑战信息，存放到全局变量challenge中
	 * @param c   			校验块数
	 * @param allBlocks   	全部块数
	 * 
	 */
	public Chal[] challengeGen(int c,int allBlocks,String fileId){
		int []ran=new int[c];
		ran=GenerateRandom.random(1,allBlocks,c); //1-allBlocks中的c个不同的数
		Chal[]challenge=new Chal[c];		
		//生成每块对应的随机数vi
		for(int i=0;i<c;i++){			
			challenge[i]=new Chal(ran[i],pairing.getZr().newRandomElement());
		}
		this.fileId=fileId;		
		return challenge;
	}




	/**
	 * CSP构建数据完整性证据proof
	 * @param vi 每个挑战块对应的随机数	
	 * @param ti 每个块的元标签
	 * @param sigHashRoot 签名过的MHT的H(R)
	 * @return
	 */
	public Map<String,Object> genProof(Element[] vi,Element[][] mij,Element[] ti,Element[] us){
		//这里求和时存在一个问题：每项进行模域运算，还是对求和结果进行模域运算，暂时我取前者
		int s=us.length;
		int c=vi.length;			
		Element []sAggreSum=new Element[s];//存放s个数据段的累加的值
		Element aggreMul=pairing.getG1().newOneElement();
		Element aggreSum;
		//数据块的累加
		for(int k=0;k<s;k++){
			aggreSum=pairing.getZr().newZeroElement();//每次重新生成一个初始0元素
			for(int i=0;i<c;i++){
				//sum(vi*mik)
				aggreSum=aggreSum.add(vi[i].duplicate().mulZn(mij[i][k]));
			}
			sAggreSum[k]=aggreSum;

		}
		//数据标签的累乘
		for(int i=0;i<c;i++){			
			//mul(ti^vi)
			aggreMul=aggreMul.mul(ti[i].duplicate().powZn(vi[i]));
		}

		//根据mi生成对应的{h(mi),Qi},发送给verifier用于生成R以便验证
		//全局变量proof保存信息
		Map<String,Object> proof=new HashMap<String,Object>(3);
		proof.put("sAggreSum", sAggreSum);
		proof.put("aggreMul", aggreMul);		
		return proof;


	}


	/**
	 * 根据CSP发来的Proof,校验者验证Proof是否正确	
	 * @param v 公钥	
	 * @return  true或false
	 */
	public boolean proofVerify(Chal[]challenge,Element v, Map<String,Object> proof,Element[]us){

		int s=us.length;		
		Element aggreMul=(Element)proof.get("aggreMul");
		Element[] sAggreSum=(Element[])(proof.get("sAggreSum"));
		Item[] id=(Item[])proof.get("id");

		//h(Idi)^vi
		int c=id.length;
		Element aggreBlock=pairing.getG1().newOneElement();
		for(int i=0;i<c;i++){
			byte[] data=new BigInteger(fileId.getBytes()).add(id[i].getId()).toByteArray();
			Element Hid=pairing.getG1().newElementFromHash(data,0,data.length);
			Element tmp=Hid.duplicate().powZn(challenge[i].random);
			aggreBlock=aggreBlock.duplicate().mul(tmp);
		}


		//∏u^μ
		Element u_=pairing.getG1().newOneElement();
		for(int j=0;j<s;j++){					
			u_=u_.mul(us[j].powZn(sAggreSum[j]));
		}
		Element l=aggreBlock.mul(u_);	    
		Element temp3 =pairing.pairing(aggreMul, g2);		
		Element temp4 = pairing.pairing(l, v);			
		return temp3.equals(temp4)? true :false;

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
