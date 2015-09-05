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
import MHT.MHTPADD_02.Chal;
import MHT.MerkleHashTree.Node;

/**
 * 测试MHTPADD_02的功能批量校验功能
 * @author MichaelSun
 *
 */
public class TestMHTPADD_02_bath {

	public static void main (String [] args) throws Exception{
		String fileName="readFileBlock.txt";
		int s=20;				//每块的段数
		int sectorSize=200;		//160bit
		int blockSize=s*sectorSize/1000;//以k为单位				
		int K=2;		//一次对两个用户的文件进行校验
		int [] kc={6,6};//每个挑战都为6块
		//计时器
		Stopwatch start=new  Stopwatch();
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_02 mhtPDP=new MHTPADD_02(false,"pairing/e/e.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//初始设置
		StdOut.println("-------------初始化参数设置------------");
		mhtPDP.setup();
		
		//生成密钥和随机值
		Map<Integer,Map<String,Element>> userKeys=new HashMap<Integer,Map<String,Element>>(K);
		List<Element []>kus=new ArrayList<Element[]>(K);
		for(int k=0;k<K;k++){
			userKeys.put(k, mhtPDP.keyGen());//密钥生成		
			kus.add(mhtPDP.pusGen(s));//用户秘密值
		}
		
		//对文件进行预处理
		StdOut.println("\n-------------对文件预处理------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, mhtPDP.getPairing().getZr());
		Element[][] sectors=HDFSFileOperation.sectors;
		Element[] gdata=mhtPDP.allGElement(pdata);		
		int fileBlocks=pdata.length;		
		StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");

		//构建MHT-暂且所有挑战的root相同
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();
		
		StdOut.println("\n-------------"+K+"个用户生成元信息------------");
		Stopwatch dataOwnerTime=new Stopwatch();
		Element[][]kblockTags=new Element[K][fileBlocks];
		Element[] ksigHashRoot=new Element[K];
		for(int k=0;k<K;k++){
			//元数据生成				
			for(int i=0;i<fileBlocks;i++){		
				kblockTags[k][i]=mhtPDP.metaGen(i,gdata[i],userKeys.get(k).get(MHTPADD_02.SECRETKEY),sectors[i],kus.get(k));
			}
			ksigHashRoot[k]=mhtPDP.sigRoot(Root, userKeys.get(k).get(MHTPADD_02.SECRETKEY));

		}
		StdOut.println("DO耗时："+dataOwnerTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------产生挑战信息------------");
		List<Chal[]> challenges=new ArrayList<Chal[]>(K);		
		for(int k=0;k<K;k++)
			challenges.add(mhtPDP.challengeGen(kc[k],fileBlocks));
		StdOut.println("\n-------------发出挑战------------");
		


		StdOut.println("\n==============Cloud Service Provider==============\n");

		Stopwatch cspTime=new Stopwatch();
		StdOut.println("-------------生成证据------------");	
		List<List<Element[]>> kmij=new ArrayList<List<Element[]>>(K);
		List<int[]> kblockNumChal=new ArrayList<int[]>(K);
		List<Element[]> kti=new ArrayList<Element[]>(K);
		List<Element[]> kHmi=new ArrayList<Element[]>(K);

		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])challenges.get(k);
			int CBCounts=chal.length;//挑战的块的数量
			int [] blockNumChal=new int[CBCounts]; 
			List<Element[]> mij=new ArrayList<Element[]>(CBCounts);
			Element[] ti=new Element[CBCounts];
			Element[] Hmi=new Element[CBCounts];
			for(int i=0;i<CBCounts;i++){
				Element[]mj=new Element[s];
				blockNumChal[i]=chal[i].num;//1-n			
				ti[i]=kblockTags[k][chal[i].num-1];
				Hmi[i]=gdata[chal[i].num-1];
				for(int j=0;j<s;j++){
					mj[j]=sectors[chal[i].num-1][j].duplicate();//读取数据
				}
				mij.add(mj);
			}
			kmij.add(mij);
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
		Map<String,Object>proof=mhtPDP.genBathProof(challenges, kmij, kti,s);	
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
		BigInteger[] errorKNewRoot=new BigInteger[K];//错误的测试数据
		for(int k=0;k<K;k++){
			//校验者根据块信息计算Root			
			knewRoot[k]=new BigInteger(mht.getRootByAuxiliaryIndex((Map<String,Object>)kaai.get(k),kblockNumChal.get(k)));
			errorKNewRoot[k]=BigInteger.ONE;
		}

		StdOut.println("\n-------------验证数据块------------");
		//检查证据
		Element[] kPublicKeys=new Element[K];
		for(int k=0;k<K;k++){
			kPublicKeys[k]=userKeys.get(k).get(MHTPADD_02.PUBLICKEY);
		}
		boolean rTrue=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,kus,proof);
		boolean rFalse1=mhtPDP.proofBathVerify(challenges,errorKNewRoot,kPublicKeys,kus,proof);//MHT的root错误
		Element T=(Element)proof.get("kaggreMul");
		proof.put("kaggreMul", T.twice());
		boolean rFalse2=mhtPDP.proofBathVerify(challenges,knewRoot,kPublicKeys,kus,proof);

		StdOut.println("耗时："+verTime.elapsedTime()+" ms.");		
		//验证结果
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------证据有效，数据完整------------");
		StdOut.println("总耗时："+start.elapsedTime()+" ms.");
	}

}
