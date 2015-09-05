package IHT;
import java.math.BigInteger;

import tool.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
/**
 * ���ļ��鹹��������ϣ��
 * @author MichaelSun
 * @version 1.0
 * @date 2014-12-22
 */
public class IndexHashTable {
	private String fileId;	//�ļ���ʶ
	private int n;			//�ļ�����

	private Element[] Hids;	//��ŶԱ���ӳ�䵽G�е���Ϣ�������ǩʱ����

	public	IndexHashTable(String fileId,int n){
		this.fileId=fileId;
		this.n=n;		
		Hids=new Element[n+1];
	}

	//��ϣ�������ڲ���
	public static class Item{
		private int index; //����߼�����
		private int Bi;    //���
		private int vi;		//�汾��
		private Element Ri;		//Zr�е������
		private Element si;		//�Ա������ǩ������

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
		//����ǩ��
		public String getContact2(){
			return String.valueOf(index)+String.valueOf(Bi)+String.valueOf(vi)+Ri.toString()+si.toString();		
		}

		//ָ���ָ���
		public String toString(String separator){
			return String.valueOf(index)+separator+String.valueOf(Bi)+separator+String.valueOf(vi)+separator+Ri.toString()+separator+si.toString();		

		}
		//Ĭ���Կո�ָ�
		public String toString(){
			return String.valueOf(index)+" "+
					String.valueOf(Bi)+" "+
					String.valueOf(vi)+" "+
					Ri.toString()+" "+
					si.toString();		
		}

	}

	/**
	 * ������ǩ��������������ϣ��IHT������������������
	 * 
	 * @param r 	����������������Zr�е������
	 * @param x	 	ǩ��˽Կ
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
			Hids[i]=Hid;	//H(fileId||i||Bi||vi||R)->G�н����ŵ�Hids��
			Element si=Hid.duplicate().powZn(x);
			iht[i]=new Item(i,i,1, Ri,si);		
		}
		return iht;
	}

	/**
	 * ������ǩ��������������ϣ��IHT����R������������
	 * 
	 * @param r 	����������������Zr�е������
	 * @param x	 	ǩ��˽Կ
	 * @param G		H(id)->G
	 * @param pdata ���ݿ���Ϣ
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
			Hids[i]=Hid;	//�����м���
			Element si=Hid.duplicate().powZn(x);//ǩ��
			iht[i]=new Item(i,i,1, Ri,si);		
		}
		return iht;
	}
	/**
	 * ������ǩ��������������ϣ��IHT����ǩ���ü�ֵ��ϣ��R��������
	 * @param r 	����������������Zr�е������
	 * @param hashKey	 s+1��������ĺ�
	 * @param G		H(id)->G�����ⲿ����ʵ�����÷��������㣬��Ϊ�ͻ����ǲ�����IHT
	 * @param pdata ���ݿ���Ϣ
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
			//�˴��õ��Ǵ������ӷ���λ��������160bit�������string����λ��̫����ǰ160bit��ͬ����ӳ����hashֵ��ͬ��ǩ��Ҳ��ͬ                                                                                                                                                                                                                                                                                                                                                                    
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
