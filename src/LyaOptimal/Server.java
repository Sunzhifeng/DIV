package LyaOptimal;

import java.util.ArrayList;
import java.util.List;

public class Server{  
	public static final int IDLE=0; //����������
	public static final int COMPUTING=1;//����������
	public static final int TASKBUFF=1;
	public static final double Q0=0.0;  //��ʼ����ʱ����г���Ϊ0.0
	public  int task=0;
	int id; 	//���������
	double s;		//�������ļ����ٶ�	
	double queueTime;	//�������Ķ��г��ȣ������ڻ���Ҫ�����ʱ��
	List<Integer>  tasksBuff;
	int state;		//��������״̬��0.���еȴ���1.����״̬
	public Server(){

	}
	public Server(int id ,double s,double queueTime,int taskBuff,int state ){
		this.id=id;
		this.s=s;	
		this.queueTime=queueTime;
		this.tasksBuff=new ArrayList<Integer>(taskBuff);
		this.state=state;
	}
}
