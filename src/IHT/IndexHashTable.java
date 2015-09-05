package IHT;
import java.math.BigInteger;

import tool.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
/**
 * 对文件块构建索引哈希表
 * @author MichaelSun
 * @version 1.0
 * @date 2014-12-22
 */
public class IndexHashTable {
	private String fileId;	//文件标识
	private int n;			//文件块数

	private Element[] Hids;	//存放对表项映射到G中的信息，计算标签时有用

	public	IndexHashTable(String fileId,int n){
		this.fileId=fileId;
		this.n=n;		
		Hids=new Element[n+1];
	}

	//哈希表表项的内部类
	public static class Item{
		private int index; //块的逻辑索引
		private int Bi;    //块号
		private int vi;		//版本号
		private Element Ri;		//Zr中的随机数
		private Element si;		//对表项进行签名保护

		public Item(int index,int Bi,int vi,Element Ri,Element si){
			this.index=index;
			this.Bi=Bi;
			this.vi=vi;
			this.Ri=Ri;
			this.si=si;
		}

		public BigInteger getId(){
			BigInteger id=bigIntegerADD(5,
					BigInteger.valueOf(index),
					BigInteger.valueOf(Bi),
					BigInteger.valueOf(vi),
					Ri.toBigInteger(),
					si.toBigInteger());
			return id;
		}
		//包含签名
		public String getContact2(){
			return String.valueOf(index)+String.valueOf(Bi)+String.valueOf(vi)+Ri.toString()+si.toString();		
		}

		//指定分隔符
		public String toString(String separator){
			return String.valueOf(index)+separator+String.valueOf(Bi)+separator+String.valueOf(vi)+separator+Ri.toString()+separator+si.toString();		

		}
		//默认以空格分隔
		public String toString(){
			return String.valueOf(index)+" "+
					String.valueOf(Bi)+" "+
					String.valueOf(vi)+" "+
					Ri.toString()+" "+
					si.toString();		
		}

	}

	/**
	 * 构建带签名保护的索引哈希表IHT——不包含数据内容
	 * 
	 * @param r 	大素数，用于生成Zr中的随机数
	 * @param x	 	签名私钥
	 * @param G		H(id)->G
	 */
	public Item[] createIHT(Field r,Element x,Field G){	
		Element eleZero=r.newZeroElement();
		Item[] iht=new Item[n+1];
		iht[0]=new Item(0,0,0,eleZero,eleZero);
		Hids[0]=eleZero;
		for(int i=1;i<=n;i++){		
			Element Ri=r.newRandomElement();
			//si=(H(fileId||i||Bi||vi||R))^x
			String data=(fileId+String.valueOf(i)+String.valueOf(i)+String.valueOf(1)+Ri.toString());
			Element Hid=G.newElementFromHash(data.getBytes(),0,data.getBytes().length);
			Hids[i]=Hid;	//H(fileId||i||Bi||vi||R)->G中结果存放到Hids中
			Element si=Hid.duplicate().powZn(x);
			iht[i]=new Item(i,i,1, Ri,si);		
		}
		return iht;
	}

	/**
	 * 构建带签名保护的索引哈希表IHT——R包含数据内容
	 * 
	 * @param r 	大素数，用于生成Zr中的随机数
	 * @param x	 	签名私钥
	 * @param G		H(id)->G
	 * @param pdata 数据块信息
	 */
	public Item[] createIHT(Field r,Element x,Field G,Element[]pdata){	
		Element eleZero=r.newZeroElement();
		Item[] iht=new Item[n+1];
		iht[0]=new Item(0,0,0,eleZero,eleZero);
		Hids[0]=eleZero;
		for(int i=1;i<=n;i++){	
			//Ri=h(mi||Bi||vi)
			String dataR=pdata[i-1].toString()+String.valueOf(i)+String.valueOf(1);
			Element Ri=r.newElementFromHash(dataR.getBytes(), 0, dataR.length());

			//si=(H(fileId||i||Bi||vi||Ri))^x
			String data=(fileId+String.valueOf(i)+String.valueOf(i)+String.valueOf(1)+Ri.toString());
			Element Hid=G.newElementFromHash(data.getBytes(),0,data.getBytes().length);
			Hids[i]=Hid;	//保存中间结果
			Element si=Hid.duplicate().powZn(x);//签名
			iht[i]=new Item(i,i,1, Ri,si);		
		}
		return iht;
	}
	/**
	 * 构建带签名保护的索引哈希表IHT——签名用键值哈希、R存放随机数
	 * @param r 	大素数，用于生成Zr中的随机数
	 * @param hashKey	 s+1个随机数的和
	 * @param G		H(id)->G——这部分其实可以让服务器计算，因为客户端是不保存IHT
	 * @param pdata 数据块信息
	 */
	public Item[] createIHT2(Field r,Element hashKey,Field G,Element[]pdata){	
		Element eleZero=r.newZeroElement();
		Item[] iht=new Item[n+1];
		iht[0]=new Item(0,0,0,eleZero,eleZero);
		Hids[0]=eleZero;
		for(int i=1;i<=n;i++){	
			
			//Ri<-Zp
			Element Ri=r.newRandomElement();
			
			//H=h(x||mi||i||Bi||vi||Ri)
			//此处用的是大整数加法，位数保持在160bit，如果用string连接位数太长且前160bit相同，再映射后的hash值相同，签名也相同                                                                                                                                                                                                                                                                                                                                                                    
			BigInteger dataR=bigIntegerADD(6,hashKey.toBigInteger(),pdata[i-1].toBigInteger(),BigInteger.valueOf(i),BigInteger.valueOf(i),BigInteger.ONE,Ri.toBigInteger());
			Element Hmac=r.newElementFromHash(dataR.toByteArray(), 0, dataR.bitLength());

			//id=(fileId||i||Bi||Vi||Ri||Si)
			BigInteger data=bigIntegerADD(6,new BigInteger(fileId.getBytes()),BigInteger.valueOf(i),BigInteger.valueOf(i),BigInteger.ONE,Ri.toBigInteger(),Hmac.toBigInteger());
			Hids[i]=G.newElementFromHash(data.toByteArray(),0,data.bitLength());
			iht[i]=new Item(i,i,1, Ri,Hmac);
		}
		return iht;
	}
	public static BigInteger bigIntegerADD(int count,BigInteger ...param){
		BigInteger sum=BigInteger.ZERO;
		for(int i=0;i<count;i++){
			sum=sum.add(param[i]);
		}
		return sum;
	}
	public Element[] getHids(){
		return Hids;
	}

	public String getFileId() {
		return fileId;
	}

	

}
