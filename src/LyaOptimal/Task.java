package LyaOptimal;

public class Task{
	public static final int COMPLETED=1;
	public static final int WAITING=0;
	public static final int RUNNING=2;
	int id;		//������
	double c;		//������
	double t; 		//�������ʱ������
	int state;  //�����״̬��0�ȴ���1��ɣ�2����ִ��
	public Task(int id,double c,double t){
		this.id=id;
		this.c=c;
		this.t=t;
	}
}