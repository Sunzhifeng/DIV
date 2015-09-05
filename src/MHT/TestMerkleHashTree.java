package MHT;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import sigAlg.SHACoder;
import tool.StdOut;

public class TestMerkleHashTree {
	public static void printTree(MerkleHashTree.Node[]a){
		for(int j=1;j<a.length;j++){			
			if(a[j].del==1)
				//for(i=0;i<a[j].value)
			StdOut.print(new String(Hex.encode(a[j].value))+" ");			
			
		}
	}
    public static void printIndex(int[] b){
    	for(int i=0;i<b.length;i++){
			StdOut.print(b[i]+" ");
		}
    }
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		String[] data={"a","b","c","d","e"};		
		MerkleHashTree mht=new MerkleHashTree(null);
		
		//创建MHT
		mht.createMHT();		
		
		printTree(mht.getHashBlockValue());
		StdOut.println();
		printIndex(mht.getHashBlockIndex());
		StdOut.println();
		
		//修改MHT
		mht.modify(2, SHACoder.encodeSHA("i".getBytes()));	
		printTree(mht.getHashBlockValue());
		StdOut.println();
		printIndex(mht.getHashBlockIndex());
		StdOut.println();
		
		//插入MHT
		mht.insert(2, SHACoder.encodeSHA("k".getBytes()));
		printTree(mht.getHashBlockValue());
		StdOut.println();
		printIndex(mht.getHashBlockIndex());
		StdOut.println();
		//删除节点
		mht.delete(3);
		printTree(mht.getHashBlockValue());
		StdOut.println();
		printIndex(mht.getHashBlockIndex());
		StdOut.println();
		
		//获得辅助索引
		MerkleHashTree.Node[] aai=mht.getAuxiliaryIndex(1);
		printTree(aai);
		StdOut.println();
		
	    
		
	}

}
