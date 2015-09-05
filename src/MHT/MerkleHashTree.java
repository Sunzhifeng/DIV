package MHT;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;
import sigAlg.SHACoder;
import it.unisa.dia.gas.jpbc.*;
/**
 * ������Merkle��ϣ���ṹ
 * @author MichaelSun
 * @version 2.0
 * @date 2014.11.17
 */
public class MerkleHashTree {		
	//��˳��ṹ������ſ��ϣֵ������,0λ�ô������ײ�Ҷ�ڵ������1��nΪ�ļ�������
	private int[] hashBlockIndex;
	//���ṹ�нڵ��ֵ ��0λ�ò��ã�1��2n-1 ���MHT���ṹ
	private Node[]  hashBlockValue;//1λ�ô������h(H(mi))
	private Node[] leafs; //Ҷ�ڵ�����
	private int n;			//Ҷ�ڵ����
	private int allNodes;   //�������нڵ����
	private int h;	        //���ĸ߶�
	private int hIndex;     //��ײ���׸�Ҷ�ڵ��λ��
	boolean fullMHT=false;  //������MHT�Ƿ�Ϊ��������
	public static class Node {
		byte[] value=null;
		boolean isLeaf; 		//�Ƿ�ΪҶ�ڵ㣬ɾ��ʱ�����ã�
		int parent ; 			//���ڵ���,�ڵ����ʱ����	
		int height ; 			// node height in tree
		int del=1;  		 	//�ڵ��Ƿ�ɾ����־��0ɾ����1δɾ��
		int leftChild=-1; 		//����
		int rightChild=-1;		//�Һ���
		boolean left;			//��ǰ�ڵ�����֦�ڵ㣿
	}
	/**
	 * ��ʼ�����ṹ����Ϣ
	 * @param data Ҷ�ӽڵ���h(H(m))
	 * @throws Exception 
	 */
	public MerkleHashTree(Element[] data) throws Exception{
		this.n=data.length;
		//n=3;
		this.allNodes=2*n-1;

		//n��Ҷ�ӽڵ�=�����ĸ߶�h
		this.h=(int)Math.ceil((Math.log(n)/Math.log(2)))+1;

		//��h���һ���ڵ������ṹ�е�λ������ֵ
		this.hIndex=(int) Math.pow(2, h-1);
		this.hashBlockIndex=new int[n+1];		
		this.hashBlockValue=new Node[allNodes+1];
		//��ʼ����������
		for(int i=0;i<allNodes+1;i++){
			hashBlockValue[i]=new Node();
		}

		this.leafs=new Node[n+1];		
		leafs[0]=new Node();//leafs[0]����
		hashBlockIndex[0]=n;//��Ч��Ҷ�ڵ����
		//leafs[0].value=String.valueOf(n);
		for(int i=0;i<n;i++){
			leafs[i+1]=new Node();
			leafs[i+1].value=hashSHA(data[i].toBytes());
			leafs[i+1].height=h;
			leafs[i+1].isLeaf=true;
			//leafs[i+1].del=1;//δɾ��
			//leafs[i+1].leftChild=-1;
			//leafs[i+1].rightChild=-1;
		}

		if(hIndex==n){//
			fullMHT=true;
			//hashBlockValue[0]="true";
		}

		//System.out.println("n="+n+",h="+h+",hIndex"+hIndex+",allNodes="+allNodes);

	}

	/**
	 * ����MHT����һ������ȫ������
	 * @param leafs ����Ҷ�ڵ��ֵ
	 * @param n Ҷ�ڵ�ĸ���
	 * @return  ������ֵ
	 * @throws Exception 
	 */
	public byte[] createMHT() throws Exception{

		int index=0;	      
		//������h�㣬Ҷ�ӽڵ�
		for(int i=hIndex;i<=allNodes;i++){
			hashBlockValue[i].value=leafs[++index].value;
			hashBlockValue[i].parent=(int)i/2;
			hashBlockValue[i].isLeaf=true;
			hashBlockValue[i].height=h;
			hashBlockIndex[index]=i;//�ӵ�һ��λ�����
		}
		//�������µ�h-1��
		for(int j=h-1;j>=1;j--){
			int start=(int) Math.pow(2, j-1);
			int end=(int)Math.pow(2, j)-1;

			if(!fullMHT){//����MHT��h-1����Ҫ���⴦��
				int start2=(int) Math.pow(2, h-2);
				int end2=(int)Math.pow(2, h-1)-1;
				for(int m=start2;m<=end2;m++){					
					if(2*m<(2*n-1)){
						hashBlockValue[m].value=hashSHA(arraycat(hashBlockValue[2*m].value,hashBlockValue[2*m+1].value));
						hashBlockValue[m].parent=(int)m/2;
						hashBlockValue[m].isLeaf=false;
						hashBlockValue[m].height=j;
						hashBlockValue[m].leftChild=2*m;
						hashBlockValue[m].rightChild=2*m+1;

					}else{

						hashBlockValue[m].value=leafs[++index].value;
						hashBlockValue[m].parent=(int)m/2;
						hashBlockValue[m].height=j;
						hashBlockValue[m].isLeaf=true;
						hashBlockIndex[index]=m;
					}
				}
				fullMHT=true;
				continue;
			}

			for(int k=start;k<=end;k++){			
				hashBlockValue[k].value=hashSHA(arraycat(hashBlockValue[2*k].value,hashBlockValue[2*k+1].value));
				hashBlockValue[k].parent=(int)k/2;
				hashBlockValue[k].height=j;
				hashBlockValue[k].isLeaf=false;
				hashBlockValue[k].leftChild=2*k;
				hashBlockValue[k].rightChild=2*k+1;
			}
		}
		return hashBlockValue[1].value;
	}
	/**
	 * �������¼���ROOT��ֵ����ֻ��value��ֵ����
	 * @param i �ӵ�i��leaf�ڵ㿪ʼ����
	 * @param m �ڵ��ֵ
	 * @return  ����
	 * @throws Exception 
	 */
	public byte[] upToRoot(int k) throws Exception{//�ӵ�i��λ�ÿ�ʼ����

		while(k>1){//k=1������Root
			if(k%2==1){//��֦����֦			
				k=k-1;
			}
			int kParent=hashBlockValue[k].parent;
			hashBlockValue[kParent].value=hashSHA(arraycat(hashBlockValue[k].value,hashBlockValue[k+1].value));
			k=kParent;
		}


		return hashBlockValue[1].value;
	}
	/**
	 * �޸ĺ���¼���Root
	 * @param i
	 * @param m 
	 * @return
	 * @throws Exception 
	 */
	public byte[] modify(int i,byte[] m) throws Exception{
		int k=hashBlockIndex[i];
		hashBlockValue[k].value=m;
		return upToRoot(k);
	}
	/**
	 * �ڵ�i��Ҷ�ڵ�����һ��Ԫ��m
	 * @param i
	 * @param m
	 * @return
	 * @throws Exception 
	 */
	public byte[] insert(int i,byte[] m) throws Exception{//ֻ����һ��Ԫ��
		//ע�⣺������M1ǰ�Ĳ����ݲ�����
		resize(1);
		n=n+1;//Ҷ�ӽڵ���Ŀ+1
		allNodes=allNodes+2;		

		//�޸�ǰ��i���ڵ����ṹ��λ��
		int indexi=hashBlockIndex[i];	   
		hashBlockValue[allNodes-1].value=hashBlockValue[indexi].value;
		hashBlockValue[allNodes-1].parent=indexi;
		hashBlockValue[allNodes-1].isLeaf=true;//Ҷ�ڵ����Һ��ӽڵ㶼Ϊ�գ����ش���-1
		hashBlockValue[allNodes-1].height=hashBlockValue[indexi].height+1;

		hashBlockValue[allNodes].value=m;		
		hashBlockValue[allNodes].parent=indexi;
		hashBlockValue[allNodes].height=hashBlockValue[indexi].height+1;
		hashBlockValue[allNodes].isLeaf=true;
		hashBlockIndex[i]=allNodes-1;

		//��i+1��n��ֵ˳�����
		for(int j=n-1;j>i;j--){
			hashBlockIndex[j+1]=hashBlockIndex[j];
		}
		//��i+1��λ�ò���m����λ�ã������ṹ�����һ��Ԫ�ص�λ��allNodes
		hashBlockIndex[i+1]=allNodes;		
		hashBlockValue[indexi].value=hashSHA(arraycat(hashBlockValue[allNodes-1].value,hashBlockValue[allNodes].value));
		hashBlockValue[indexi].isLeaf=false;
		hashBlockValue[indexi].leftChild=allNodes-1;
		hashBlockValue[indexi].rightChild=allNodes;
		return upToRoot(indexi);
	}
	
	/**
	 * ɾ����i��Ҷ�ӽڵ�
	 * @param i
	 * @return
	 * @throws Exception 
	 */
	public byte[] delete(int i) throws Exception{//ɾ��ʱ���Բ���������Ĵ�С������һ��ɾ����־
		int indexi=hashBlockIndex[i];//Ҫɾ���ڵ�����ṹ����
		int indexiParent=hashBlockValue[indexi].parent;
		hashBlockValue[indexi].del=0;//ɾ��
		hashBlockValue[indexi].height=0;
		if(indexi%2==1){//ɾ����֦����ֵ֦����
			if(hashBlockValue[indexi-1].isLeaf){//��֦��Ҷ�ڵ�
				hashBlockValue[indexiParent].value=hashBlockValue[indexi-1].value;
				hashBlockValue[indexiParent].isLeaf=true;
				hashBlockValue[indexiParent].leftChild=-1;
				hashBlockValue[indexiParent].rightChild=-1;
				hashBlockValue[indexi-1].del=0;
				hashBlockValue[indexi-1].height=0;
			}else{//��֦Ϊ��Ҷ�ӽڵ�

				hashBlockValue[indexiParent].value=hashBlockValue[indexi-1].value;
				hashBlockValue[indexi-1].del=0;
				hashBlockValue[indexi-1].height=0;
				hashBlockValue[indexiParent].leftChild=hashBlockValue[indexi-1].leftChild;
				hashBlockValue[indexiParent].rightChild=hashBlockValue[indexi-1].rightChild;
				//indexi-1�������ĸ߶ȼ�1
				subTreeNodeHeight(indexiParent);
				hashBlockValue[indexiParent].height+=1;//
			}
		}else{//ɾ����֦����֦ΪҶ�ڵ�
			if(hashBlockValue[indexi+1].isLeaf){//��ֵΪҶ�ڵ���
				hashBlockValue[indexiParent].value=hashBlockValue[indexi+1].value;
				hashBlockValue[indexiParent].isLeaf=true;
				hashBlockValue[indexiParent].leftChild=-1;
				hashBlockValue[indexiParent].rightChild=-1;
				hashBlockValue[indexi+1].del=0;
				hashBlockValue[indexi+1].height=0;
			}else{//��֦��Ҷ�ӽڵ�
				hashBlockValue[indexiParent].value=hashBlockValue[indexi+1].value;
				hashBlockValue[indexi+1].del=0;
				hashBlockValue[indexi+1].height=0;
				hashBlockValue[indexiParent].leftChild=hashBlockValue[indexi+1].leftChild;
				hashBlockValue[indexiParent].rightChild=hashBlockValue[indexi+1].rightChild;
				//indexi-1�������ĸ߶ȼ�1
				subTreeNodeHeight(indexiParent);
				hashBlockValue[indexiParent].height+=1;
			}
		}

		return upToRoot(indexiParent);
	}
	//�޸��������ڵĲ����
	public void subTreeNodeHeight(int root){
		hashBlockValue[root].height-=1;
		int indexl =hashBlockValue[root].leftChild;			
		if(indexl==-1){
			return;
		}

		subTreeNodeHeight(indexl);
		subTreeNodeHeight(indexl+1);

	}
	/**
	 * ��õ�i��Ҷ�ڵ�ĸ��������ռ�
	 * @param i  Ҷ�ڵ���
	 * @return   ���������ռ�
	 * @throws Exception 
	 */
	public Node[] getAuxiliaryIndex(int i) throws Exception{
		int indexInTree=hashBlockIndex[i];//�õ���������
		int h=hashBlockValue[indexInTree].height;
		Node[] aai=new Node[h+1];//0,1���ã�2-h���i�ĸ���������ÿ��һ��

		for(int k=h;k>1;k--){

			if(indexInTree%2==0){//��ǰ�ڵ�����֦

				aai[k]=hashBlockValue[indexInTree+1];
				aai[k].left=false;
				indexInTree=indexInTree/2;
			}else{//��֦
				hashBlockValue[indexInTree-1].left=true;
				aai[k]=hashBlockValue[indexInTree-1];
				aai[k].left=true;
				indexInTree=(indexInTree-1)/2;
			}


		}

		return aai;
	}
	//���ݸ������������µ�MHTRoot
	public byte[] newRootGen(Node[]aai,int i) throws Exception{//iΪ�ڼ����ڵ�
		Node inode=leafs[i];
		//boolean left=((i%2==1)?true:false);//
		//inode.left=left;
		byte[] temp;		
		int hi=aai.length-1;//��h��
		//StdOut.println("newROotGen"+inode.value+" "+aai[hi].value);
		//h��
		if(!aai[hi].left){//����֦
			temp=hashSHA(arraycat(inode.value,aai[hi].value));
		}else{
			temp=hashSHA(arraycat(aai[hi].value,inode.value));

		}
		//����h-1
		for(int j=hi-1;j>1;j--){				
			//left=(aai[j].parent%2==0)&&(aai[j].leftChild%2==0)?true:false;//���ڵ㡢���Ӷ�Ϊ��֦����ǰ�ڵ�һ��Ϊ��֦
			if(aai[j].left){
				temp=hashSHA(arraycat(aai[j].value,temp));				
			}else{
				temp=hashSHA(arraycat(temp,aai[j].value));

			}
		}
		//StdOut.print("temp:");
		//StdOut.println(temp);
		byte[]newRoot=temp;
		return newRoot;
	}
	
	public Map<String,Object> genChalAAI(int []c) throws Exception{
		int length=c.length;
		Map<String,Object> chalAAI=new HashMap<String,Object>(length);		
		for(int i=0;i<length;i++){
			chalAAI.put(Integer.toString(c[i]),getAuxiliaryIndex(c[i]) );
		}
		return chalAAI;
	}



	/**
	 * ���ݸ�����������Root
	 * @param c ��ս�Ŀ�ı�ż���
	 * @return
	 * @throws Exception
	 */
	public byte[] getRootByAuxiliaryIndex(Map<String,Object> chalAAI,int []c) throws Exception{//cΪ��������
		//StdOut.println("---------����getRootByAuxiliaryIndex()----");
		Node[] cRoot=new Node[c.length];//���ÿ���ڵ㹹����ĸ�		
		Node[] aai;
		for(int i=0;i<c.length;i++){			
			cRoot[i]=new Node();				
			aai=(Node[]) chalAAI.get(Integer.toString(c[i]));
			cRoot[i].value=newRootGen(aai,c[i]);
			//System.err.println(c[i]+":"+new String(Hex.encode(cRoot[i].value)));
		}
		Node temp=cRoot[0];
		for(int j=0;j<c.length;j++){			
			if(!new String(Hex.encode(temp.value)).equals(new String(Hex.encode(cRoot[j].value)))){
				System.err.println("getRootByAuxiliaryIndex is error!");
				break;
			}
		}
		//StdOut.println("---------�뿪getRootByAuxiliaryIndex()----");
		return cRoot[0].value;
	}
	//�㷨��û��ʵ��
	public Node[] compressAuxiliaryIndexs(int [] c){//�ϲ�c����ս��ĸ��������ռ�
		int blockNum=c.length;
		Map<Integer,Node> a=new HashMap<Integer,Node>();
		for(int i=0;i<blockNum;i++){
			boolean left=(c[i]%2==1);//���Ϊ�棬��ڵ�
			if(left){//��֦
				a.put(c[i],hashBlockValue[hashBlockIndex[c[i]]]);
				a.put(c[i]+1, hashBlockValue[hashBlockIndex[c[i]+1]]);				
			}else{
				a.put(c[i], hashBlockValue[hashBlockIndex[c[i]]]);				
				a.put(c[i]-1, hashBlockValue[hashBlockIndex[c[i]-1]]);				
			}

		}
		return null;
	}

	/**
	 *  ���Ӵ洢����Ĵ�С
	 * @param changeSize �ı�ĵ�λ����Ĭ��Ϊ1
	 */
	public void resize(int changeSize){
		int hashBlockIndexLen=hashBlockIndex.length;
		int hashBlockValueLen=hashBlockValue.length;
		int leafsLen=leafs.length;
		int [] a=new int[hashBlockIndexLen+changeSize];
		Node [] b=new Node[hashBlockValueLen+2*changeSize];
		for(int i=0;i<hashBlockValueLen+2*changeSize;i++){
			b[i]=new Node();			
		}
		Node [] c=new Node[leafsLen+changeSize];

		for(int i=0;i<leafsLen+changeSize;i++){
			c[i]=new Node();			
		}
		hashBlockIndex=copyArray(hashBlockIndex, a);
		//hashBlockIndex[0]+=changeSize;
		hashBlockValue=copyArray(hashBlockValue, b);		
		leafs=copyArray(leafs, c);
		//StdOut.print(hashBlockIndex.length+","+hashBlockValue.length);

	}
	//��������Ӧ��
	public Node[] copyArray(Node[] from,Node[]to){
		int n=from.length;
		for(int i=0;i<n;i++){
			to[i]=from[i];			
		}
		return to;
	}
	public int[] copyArray(int[] from,int[]to){
		int n=from.length;
		for(int i=0;i<n;i++){
			to[i]=from[i];
		}
		return to;
	}
	public int [] getHashBlockIndex() {
		return hashBlockIndex;
	}

	public void setHashBlockIndex(int [] hashBlockIndex) {
		this.hashBlockIndex = hashBlockIndex;
	}

	public Node[] getHashBlockValue() {
		return hashBlockValue;
	}

	public void setHashBlockValue(Node[] hashBlockValue) {
		this.hashBlockValue = hashBlockValue;
	}
	public static byte[] hashSHA(byte[] data) throws Exception {    	
		return SHACoder.encodeSHA(data);		
	}


	//���������ֽ�����
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



}
