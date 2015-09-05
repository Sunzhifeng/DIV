package fileOperation;

import tool.Sampling;
import tool.StdOut;

public class TestHDFSFileOperation {
	public static void testSample(){
		int t=Sampling.getSampleBlocks(10000, 100, 0.99);
		double w=Sampling.getSamplingRatio(10000, 100, 0.99);
		int f=Sampling.getVerifyingFrequent(10000, 10, 460, 0.99,1);
		StdOut.println("sample blocks:"+t);
		StdOut.println("sample ratio:"+w);
		StdOut.println("sample frequent:"+f);
		//分段时的处理
		int t2=Sampling.getSampleBlocks(10000,0.99,10,100);
		double w2=Sampling.getSamplingRatio(10000,0.99,10,100);
		int f2=Sampling.getVerifyingFrequent(10000,460,0.99,1,10,100);
		StdOut.println("sample blocks2:"+t2);
		StdOut.println("sample ratio2:"+w2);
		StdOut.println("sample frequent2:"+f2);

	}

	public static void main(String[] args) throws Exception {
		testSample();
	}
}
