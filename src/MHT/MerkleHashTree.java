package MHT;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;
import sigAlg.SHACoder;
import it.unisa.dia.gas.jpbc.*;
/**
 * 基本的Merkle哈希树结构
 * @author MichaelSun
 * @version 2.0
 * @date 2014.11.17
 */
public class MerkleHashTree {		
	//块顺序结构——存放块哈希值的索引,0位置存放树最底层叶节点个数，1～n为文件块数。
	private int[] hashBlockIndex;
	//树结构中节点的值 ，0位置不用，1～2n-1 存放MHT树结构
	private Node[]  hashBlockValue;//1位置存放树根h(H(mi))
	private Node[] leafs; //叶节点数组
	private int n;			//叶节点个数
	private int allNodes;   //树中所有节点个数
	private int h;	        //树的高度
	private int hIndex;     //最底层的首个叶节点的位置
	boolean fullMHT=false;  //构建的MHT是否为满二叉树
	public static class Node {
		byte[] value=null;
		boolean isLeaf; 		//是否为叶节点，删除时候有用，
		int parent ; 			//父节点编号,节点插入时有用	
		int height ; 			// node height in tree
		int del=1;  		 	//节点是否被删除标志，0删除，1未删除
		int leftChild=-1; 		//左孩子
		int rightChild=-1;		//右孩子
		boolean left;			//当前节点是左枝节点？
	}
	/**
	 * 初始化树结构等信息
	 * @param data 叶子节点存放h(H(m))
	 * @throws Exception 
	 */
	public MerkleHashTree(Element[] data) throws Exception{
		this.n=data.length;
		//n=3;
		this.allNodes=2*n-1;

		//n个叶子节点=》树的高度h
		this.h=(int)Math.ceil((Math.log(n)/Math.log(2)))+1;

		//第h层第一个节点在树结构中的位置索引值
		this.hIndex=(int) Math.pow(2, h-1);
		this.hashBlockIndex=new int[n+1];		
		this.hashBlockValue=new Node[allNodes+1];
		//初始化对象数组
		for(int i=0;i<allNodes+1;i++){
			hashBlockValue[i]=new Node();
		}

		this.leafs=new Node[n+1];		
		leafs[0]=new Node();//leafs[0]备用
		hashBlockIndex[0]=n;//有效的叶节点个数
		//leafs[0].value=String.valueOf(n);
		for(int i=0;i<n;i++){
			leafs[i+1]=new Node();
			leafs[i+1].value=hashSHA(data[i].toBytes());
			leafs[i+1].height=h;
			leafs[i+1].isLeaf=true;
			//leafs[i+1].del=1;//未删除
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
	 * 构造MHT——一颗类完全二叉树
	 * @param leafs 所有叶节点的值
	 * @param n 叶节点的个数
	 * @return  树根的值
	 * @throws Exception 
	 */
	public byte[] createMHT() throws Exception{

		int index=0;	      
		//构建第h层，叶子节点
		for(int i=hIndex;i<=allNodes;i++){
			hashBlockValue[i].value=leafs[++index].value;
			hashBlockValue[i].parent=(int)i/2;
			hashBlockValue[i].isLeaf=true;
			hashBlockValue[i].height=h;
			hashBlockIndex[index]=i;//从第一个位置添加
		}
		//构建余下的h-1层
		for(int j=h-1;j>=1;j--){
			int start=(int) Math.pow(2, j-1);
			int end=(int)Math.pow(2, j)-1;

			if(!fullMHT){//非满MHT的h-1层需要特殊处理
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
	 * 向上重新计算ROOT的值——只对value的值处理
	 * @param i 从第i个leaf节点开始调整
	 * @param m 节点的值
	 * @return  树根
	 * @throws Exception 
	 */
	public byte[] upToRoot(int k) throws Exception{//从第i个位置开始调整

		while(k>1){//k=1调整到Root
			if(k%2==1){//右枝变左枝			
				k=k-1;
			}
			int kParent=hashBlockValue[k].parent;
			hashBlockValue[kParent].value=hashSHA(arraycat(hashBlockValue[k].value,hashBlockValue[k+1].value));
			k=kParent;
		}


		return hashBlockValue[1].value;
	}
	/**
	 * 修改后从新计算Root
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
	 * 在第i个叶节点后插入一个元素m
	 * @param i
	 * @param m
	 * @return
	 * @throws Exception 
	 */
	public byte[] insert(int i,byte[] m) throws Exception{//只插入一个元素
		//注意：这里在M1前的插入暂不考虑
		resize(1);
		n=n+1;//叶子节点数目+1
		allNodes=allNodes+2;		

		//修改前的i所在的树结构的位置
		int indexi=hashBlockIndex[i];	   
		hashBlockValue[allNodes-1].value=hashBlockValue[indexi].value;
		hashBlockValue[allNodes-1].parent=indexi;
		hashBlockValue[allNodes-1].isLeaf=true;//叶节点左右孩子节点都为空，不必处理-1
		hashBlockValue[allNodes-1].height=hashBlockValue[indexi].height+1;

		hashBlockValue[allNodes].value=m;		
		hashBlockValue[allNodes].parent=indexi;
		hashBlockValue[allNodes].height=hashBlockValue[indexi].height+1;
		hashBlockValue[allNodes].isLeaf=true;
		hashBlockIndex[i]=allNodes-1;

		//将i+1～n的值顺序后移
		for(int j=n-1;j>i;j--){
			hashBlockIndex[j+1]=hashBlockIndex[j];
		}
		//在i+1的位置插入m所在位置，即树结构的最后一个元素的位置allNodes
		hashBlockIndex[i+1]=allNodes;		
		hashBlockValue[indexi].value=hashSHA(arraycat(hashBlockValue[allNodes-1].value,hashBlockValue[allNodes].value));
		hashBlockValue[indexi].isLeaf=false;
		hashBlockValue[indexi].leftChild=allNodes-1;
		hashBlockValue[indexi].rightChild=allNodes;
		return upToRoot(indexi);
	}
	
	/**
	 * 删除第i个叶子节点
	 * @param i
	 * @return
	 * @throws Exception 
	 */
	public byte[] delete(int i) throws Exception{//删除时可以不调整数组的大小，设置一个删除标志
		int indexi=hashBlockIndex[i];//要删除节点的树结构索引
		int indexiParent=hashBlockValue[indexi].parent;
		hashBlockValue[indexi].del=0;//删除
		hashBlockValue[indexi].height=0;
		if(indexi%2==1){//删除右枝，左枝值上移
			if(hashBlockValue[indexi-1].isLeaf){//左枝是叶节点
				hashBlockValue[indexiParent].value=hashBlockValue[indexi-1].value;
				hashBlockValue[indexiParent].isLeaf=true;
				hashBlockValue[indexiParent].leftChild=-1;
				hashBlockValue[indexiParent].rightChild=-1;
				hashBlockValue[indexi-1].del=0;
				hashBlockValue[indexi-1].height=0;
			}else{//左枝为非叶子节点

				hashBlockValue[indexiParent].value=hashBlockValue[indexi-1].value;
				hashBlockValue[indexi-1].del=0;
				hashBlockValue[indexi-1].height=0;
				hashBlockValue[indexiParent].leftChild=hashBlockValue[indexi-1].leftChild;
				hashBlockValue[indexiParent].rightChild=hashBlockValue[indexi-1].rightChild;
				//indexi-1的子树的高度减1
				subTreeNodeHeight(indexiParent);
				hashBlockValue[indexiParent].height+=1;//
			}
		}else{//删除左枝，右枝为叶节点
			if(hashBlockValue[indexi+1].isLeaf){//右值为叶节点你
				hashBlockValue[indexiParent].value=hashBlockValue[indexi+1].value;
				hashBlockValue[indexiParent].isLeaf=true;
				hashBlockValue[indexiParent].leftChild=-1;
				hashBlockValue[indexiParent].rightChild=-1;
				hashBlockValue[indexi+1].del=0;
				hashBlockValue[indexi+1].height=0;
			}else{//右枝非叶子节点
				hashBlockValue[indexiParent].value=hashBlockValue[indexi+1].value;
				hashBlockValue[indexi+1].del=0;
				hashBlockValue[indexi+1].height=0;
				hashBlockValue[indexiParent].leftChild=hashBlockValue[indexi+1].leftChild;
				hashBlockValue[indexiParent].rightChild=hashBlockValue[indexi+1].rightChild;
				//indexi-1的子树的高度减1
				subTreeNodeHeight(indexiParent);
				hashBlockValue[indexiParent].height+=1;
			}
		}

		return upToRoot(indexiParent);
	}
	//修改子树所在的层次数
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
	 * 获得第i个叶节点的辅助索引空间
	 * @param i  叶节点编号
	 * @return   辅助索引空间
	 * @throws Exception 
	 */
	public Node[] getAuxiliaryIndex(int i) throws Exception{
		int indexInTree=hashBlockIndex[i];//得到树中索引
		int h=hashBlockValue[indexInTree].height;
		Node[] aai=new Node[h+1];//0,1不用，2-h存放i的辅助索引，每行一个

		for(int k=h;k>1;k--){

			if(indexInTree%2==0){//当前节点在左枝

				aai[k]=hashBlockValue[indexInTree+1];
				aai[k].left=false;
				indexInTree=indexInTree/2;
			}else{//右枝
				hashBlockValue[indexInTree-1].left=true;
				aai[k]=hashBlockValue[indexInTree-1];
				aai[k].left=true;
				indexInTree=(indexInTree-1)/2;
			}


		}

		return aai;
	}
	//根据辅助索引构建新的MHTRoot
	public byte[] newRootGen(Node[]aai,int i) throws Exception{//i为第几个节点
		Node inode=leafs[i];
		//boolean left=((i%2==1)?true:false);//
		//inode.left=left;
		byte[] temp;		
		int hi=aai.length-1;//第h层
		//StdOut.println("newROotGen"+inode.value+" "+aai[hi].value);
		//h层
		if(!aai[hi].left){//在右枝
			temp=hashSHA(arraycat(inode.value,aai[hi].value));
		}else{
			temp=hashSHA(arraycat(aai[hi].value,inode.value));

		}
		//余下h-1
		for(int j=hi-1;j>1;j--){				
			//left=(aai[j].parent%2==0)&&(aai[j].leftChild%2==0)?true:false;//父节点、左孩子都为左枝，当前节点一定为左枝
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
	 * 根据辅助索引计算Root
	 * @param c 挑战的块的编号集合
	 * @return
	 * @throws Exception
	 */
	public byte[] getRootByAuxiliaryIndex(Map<String,Object> chalAAI,int []c) throws Exception{//c为块编号数组
		//StdOut.println("---------进入getRootByAuxiliaryIndex()----");
		Node[] cRoot=new Node[c.length];//存放每个节点构造出的根		
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
		//StdOut.println("---------离开getRootByAuxiliaryIndex()----");
		return cRoot[0].value;
	}
	//算法还没有实现
	public Node[] compressAuxiliaryIndexs(int [] c){//合并c个挑战块的辅助索引空间
		int blockNum=c.length;
		Map<Integer,Node> a=new HashMap<Integer,Node>();
		for(int i=0;i<blockNum;i++){
			boolean left=(c[i]%2==1);//编号为奇，左节点
			if(left){//左枝
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
	 *  增加存储数组的大小
	 * @param changeSize 改变的单位量，默认为1
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
	//泛化可以应用
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


	//连接两个字节数组
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
