package AssignTasks;

import tool.DataFilter;

public class BaseParams {
	public static final int S=10;//校验组大小，即校验者个数
	public static final int L=5; //云服务器个数
	public static final int B=500;//移动网络带宽
	public static final int n=1000;		//待检查数据块数
	public static final int M=1;		//文件大小，G
	public static final double pr=0.99; //探测率	
	public static final int bs =(int)M/n;//数据块大小
	public static final int T=10;		//用户期望完成时间

	//校验者基准功率下验证证据的计算时间函数tver(x)=ax+b	
	public static final double Ps0CPU=2.5;
	public static final double Pd0CPU=5;
	public static final double Ps0RF=1.25;
	public static final double Pd0RF=1.25;
	public static final double a=0.0065;
	public static final double b=0.163;	
	
	
	
	//基准频率f0云服务器计算证据的时间函数参数tcsp(x)=ax+b,即为校验者等待时间.
	public static final double f0=3.2; //云服务器基准CPU工作频率
	public static final double a2=0.0066;
	public static final double b2=4.634; 
	
	
	//实验中可变参数设置
	public static final double[] PsCPUi={2.0,2.1,2.2,2.3,2.4,2.5,2.6,2.7,2.8,2.9,3};
	public static final double[] PdCPUi={4.0,4.2,4.4,4.6,4.8,5.0,5.2,5.4,5.6,5.8,6};
	public static final double[] PsRFi={1,1.05,1.1,1.15,1.2,1.25,1.3,1.35,1.4,1.45,1.5};
	public static final double[] PdRFi={1,1.05,1.1,1.15,1.2,1.25,1.3,1.35,1.4,1.45,1.5};
	public static final double[] fj={0.0,2.4,2.6,2.8,3.0,3.2};
	public static final int[] wi={};
	
	/**
	 * 校验者基准功率验证证据的计算时间
	 * @param x 校验块数
	 * @return  验证证据时间
	 */
	public static double baseVerTime(int x){
		return DataFilter.roundDouble(a*x+b,3);
	}
	
	/**
	 * 服务器以基准CPU工作频率f0计算证据时间
	 * @param x 校验的块数
	 * @return  计算证据时间
	 */
	public static double baseCSTime(int x){
		return DataFilter.roundDouble(a2*x+b2,3);
	}
	

	/**
	 * 校验者在给定时间内可校验最大块数
	 * @param t	计算证据时间
	 * @return  校验证据的最大块数
	 */
	public static int verBlocks(double t,double fi)
	{
		return (int)(t*(fi/(a*f0))-b/a);	
	}

}
