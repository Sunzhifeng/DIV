package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_01.Chal;
import MHT.MerkleHashTree.Node;

/**
 * 测试MHTPADD_01的功能批量校验功能
 * @author MichaelSun
 *
 */
public class TestMHTPADD_01_bath {

	public static void main (String [] args) throws Exception{
		String fileName="readFileBlock.txt";
		int blockSize=4;//以k为单位			
		int K=2;		//一次对两个用户的文件进行校验
		int [] kc={6,6};//每个挑战都为6块
		//计时器
		Stopwatch start=new  Stopwatch();
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_01 mhtPDP=new MHTPADD_01(false,"pairing/e/e.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//初始设置
		StdOut.println("-------------初始化参数设置------------");
		mhtPDP.setup();


		//对文件进行预处理
		StdOut.println("\n-------------对文件预处理------------");
		Element[] pdata=fileOper.preProcessFile(fileName,blockSize, mhtPDP.getPairing().getZr());
		//StdOut.println("H(mi)->g：");
		Element[] gdata=mhtPDP.allGElement(pdata);
		int fileBlocks=pdata.length;
		//Element[] pdata=mhtPDP.allFieldElement(data);
		StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");

		//构建MHT
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();
		StdOut.println(new BigInteger(Root));

		Map<Integer,Map<String,Element>> userKeys=new HashMap<Integer,Map<String,Element>>(K);
		Element []ku=new Element[K];
		Element[][]kblockTags=new Element[K][fileBlocks];
		Element[] ksigHashRoot=new Element[K];

		StdOut.println("\n-------------"+K+"个用户生成元信息------------");
		Stopwatch dataOwnerTime=new Stopwatch();
		for(int k=0;k<K;k++){
			userKeys.put(k, mhtPDP.keyGen());//密钥生成		
			ku[k]=mhtPDP.genRandomU();//用户秘密值

			//元数据生成				
			for(int i=0;i<fileBlocks;i++){		
				kblockTags[k][i]=mhtPDP.metaGen(i,pdata[i],gdata[i],userKeys.get(k).get(MHTPADD_01.SECRETKEY),ku[k]);
			}
			ksigHashRoot[k]=mhtPDP.sigRoot(Root, userKeys.get(k).get(MHTPADD_01.SECRETKEY));

		}
		StdOut.println("DO耗时："+dataOwnerTime.elapsedTime()+"ms");
		

		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------产生挑战信息------------");
		List<Chal[]> challenges=new ArrayList<Chal[]>(K);		
		for(int k=0;k<K;k++)
			challenges.add(mhtPDP.challengeGen(kc[k],fileBlocks));
		StdOut.println("\n-------------发出挑战------------");
		/*for(Chal chal:challenge){
			StdOut.println("(块编号，随机数): "+"("+chal.num+","+chal.random+")");
		}*/



		StdOut.println("\n==============Cloud Service Provider==============\n");
		
		Stopwatch cspTime=new Stopwatch();
		StdOut.println("-------------生成证据------------");	
		List<Element[]> kmi=new ArrayList<Element[]>(K);
		List<int[]> kblockNumChal=new ArrayList<int[]>(K);
		List<Element[]> kti=new ArrayList<Element[]>(K);
		List<Element[]> kHmi=new ArrayList<Element[]>(K);

		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//挑战的块的数量
			int [] blockNumChal=new int[CBCounts]; 
			Element[] mi=new Element[CBCounts];
			Element[] ti=new Element[CBCounts];
			Element[] Hmi=new Element[CBCounts];
			for(int i=0;i<CBCounts;i++){
				blockNumChal[i]=chal[i].num;//1-n
				mi[i]=pdata[chal[i].num-1];
				ti[i]=kblockTags[k][chal[i].num-1];
				Hmi[i]=gdata[chal[i].num-1];
			}
			kmi.add(mi);
			kblockNumChal.add(blockNumChal);
			kti.add(ti);
			kHmi.add(Hmi);
		}

		List<Object> kaai=new ArrayList<Object>(K);
		//Element ksigHashRootAggre=mhtPDP.getPairing().getG1().newOneElement();
		for(int k=0;k<K;k++){
			kaai.add(mht.genChalAAI(kblockNumChal.get(k)));//计算辅助索引空间
		//	ksigHashRootAggre=ksigHashRootAggre.mul(ksigHashRoot[k]);
		}
		//数据累加和标签累乘
		Map<String,Object>proof=mhtPDP.genBathProof(challenges, kmi, kti);	
		proof.put("kaai",kaai);
		proof.put("kHmi",kHmi);//Hmi中的值顺序对应与挑战编号的顺序
		//proof.put("ksigHashRootAggre",ksigHashRootAggre);	//累乘MHT树根签名
		proof.put("ksigHashRoot", ksigHashRoot);
		StdOut.println(proof);
		StdOut.println("csp耗时："+cspTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		
		Stopwatch verTime=new  Stopwatch();
		StdOut.println("-------------计算并验证Root------------");		
		BigInteger[] knewRoot=new BigInteger[K];
		BigInteger[] errorKNewRoot=new BigInteger[K];
		for(int k=0;k<K;k++){
			//校验者根据块信息计算Root			
			knewRoot[k]=new BigInteger(mht.getRootByAuxiliaryIndex((Map<String,Object>)kaai.get(k),kblockNumChal.get(k)));
			errorKNewRoot[k]=BigInteger.ONE;
		}

		StdOut.println("\n-------------验证数据块------------");
		//检查证据
		Element[] kPublicKeys=new Element[K];
		for(int k=0;k<K;k++){
			kPublicKeys[k]=userKeys.get(k).get(MHTPADD_01.PUBLICKEY);
		}
		boolean rTrue=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,ku,proof);
		boolean rFalse1=mhtPDP.proofBathVerify(challenges,errorKNewRoot,kPublicKeys,ku,proof);//MHT的root错误
		Element T=(Element)proof.get("kaggreMul");
		proof.put("kaggreMul", T.twice());
		boolean rFalse2=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,ku,proof);
		
		StdOut.println("耗时："+verTime.elapsedTime()+" ms.");		
		//验证结果
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------证据有效，数据完整------------");
		StdOut.println("总耗时："+start.elapsedTime()+" ms.");
	}

}
