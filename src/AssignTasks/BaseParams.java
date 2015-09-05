package AssignTasks;

import tool.DataFilter;

public class BaseParams {
	public static final int S=10;//У�����С����У���߸���
	public static final int L=5; //�Ʒ���������
	public static final int B=500;//�ƶ��������
	public static final int n=1000;		//��������ݿ���
	public static final int M=1;		//�ļ���С��G
	public static final double pr=0.99; //̽����	
	public static final int bs =(int)M/n;//���ݿ��С
	public static final int T=10;		//�û��������ʱ��

	//У���߻�׼��������֤֤�ݵļ���ʱ�亯��tver(x)=ax+b	
	public static final double Ps0CPU=2.5;
	public static final double Pd0CPU=5;
	public static final double Ps0RF=1.25;
	public static final double Pd0RF=1.25;
	public static final double a=0.0065;
	public static final double b=0.163;	
	
	
	
	//��׼Ƶ��f0�Ʒ���������֤�ݵ�ʱ�亯������tcsp(x)=ax+b,��ΪУ���ߵȴ�ʱ��.
	public static final double f0=3.2; //�Ʒ�������׼CPU����Ƶ��
	public static final double a2=0.0066;
	public static final double b2=4.634; 
	
	
	//ʵ���пɱ��������
	public static final double[] PsCPUi={2.0,2.1,2.2,2.3,2.4,2.5,2.6,2.7,2.8,2.9,3};
	public static final double[] PdCPUi={4.0,4.2,4.4,4.6,4.8,5.0,5.2,5.4,5.6,5.8,6};
	public static final double[] PsRFi={1,1.05,1.1,1.15,1.2,1.25,1.3,1.35,1.4,1.45,1.5};
	public static final double[] PdRFi={1,1.05,1.1,1.15,1.2,1.25,1.3,1.35,1.4,1.45,1.5};
	public static final double[] fj={0.0,2.4,2.6,2.8,3.0,3.2};
	public static final int[] wi={};
	
	/**
	 * У���߻�׼������֤֤�ݵļ���ʱ��
	 * @param x У�����
	 * @return  ��֤֤��ʱ��
	 */
	public static double baseVerTime(int x){
		return DataFilter.roundDouble(a*x+b,3);
	}
	
	/**
	 * �������Ի�׼CPU����Ƶ��f0����֤��ʱ��
	 * @param x У��Ŀ���
	 * @return  ����֤��ʱ��
	 */
	public static double baseCSTime(int x){
		return DataFilter.roundDouble(a2*x+b2,3);
	}
	

	/**
	 * У�����ڸ���ʱ���ڿ�У��������
	 * @param t	����֤��ʱ��
	 * @return  У��֤�ݵ�������
	 */
	public static int verBlocks(double t,double fi)
	{
		return (int)(t*(fi/(a*f0))-b/a);	
	}

}