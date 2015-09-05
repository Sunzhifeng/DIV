/******************************************************
 ************** �ͻ����û�����HDFS�е��ļ�****************
 ******************************************************
 */

package fileOperation;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.io.IOUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;
public class HadoopFile {
	//public static String hdfsPath="hdfs://master:9000/user/sunzhifeng/input";

	/**
	 * �����������ļ��ϴ���hadoop��
	 * @param localfile �����ļ�·��
	 * @param hdfsDirectory hdfs�ļ�Ŀ¼
	 * @throws Exception
	 */
	public static void upload(String localfile,String hdfsDirectory) throws Exception {
		Configuration conf = new Configuration();		
		FileSystem hdfs = FileSystem.get(URI.create(hdfsDirectory),conf);
		Path src = new Path(localfile);
		Path dst = new Path(hdfsDirectory);

		//ִ���ϴ�����������ӡ��ʾ��Ϣ
		hdfs.copyFromLocalFile(src, dst);
		System.out.println("Upload to " +hdfsDirectory);

		listFiles(hdfs,dst);

	}
	/**
	 * ��HDFS�е�ĳ���ļ����ص�����
	 * @param hdfsFile		Ҫ���ص��ļ�
	 * @param localPath		����·��	
	 * @throws Exception
	 */
	public static void download(String hdfsFile,String localPath)throws Exception{
		Configuration conf = new Configuration();			
		FileSystem hadoopFS=FileSystem.get(URI.create(hdfsFile),conf);
		Path hdfsPath=new Path(hdfsFile);
		FSDataInputStream fsIn=hadoopFS.open(hdfsPath);
		OutputStream fsout = new FileOutputStream(localPath+"/"+hdfsPath.getName());  
		IOUtils.copyBytes(fsIn, fsout, 4096,true);
		System.out.println("Download to " +localPath);

	}


	/**
	 * ɾ��HDFS�е�ĳ���ļ� 	
	 * @param hdfsfile	Ҫɾ�����ļ�����������·��
	 * @throws Exception
	 */
	public static void delete(String hdfsfile) throws Exception {
		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsfile),conf);		
		Path hdfsPath = new Path(hdfsfile);
		boolean exit=hdfs.exists(hdfsPath);
		if(!exit){
			System.err.println(hdfsPath.getName()+"is not exist!can't delete��");
			return;
		}
		Path p= hdfsPath.getParent();//���ɾ���ļ���Ŀ¼�ĸ�Ŀ¼
		boolean ok = hdfs.delete(hdfsPath, true);//ɾ��Ŀ¼����true
		System.out.println(ok ? "delete successfully!" : "delete unsuccessfully! ");

		//��ǰĿ¼�µ��ļ�
		listFiles(hdfs,p);

	}

	/**
	 * ��ȡHDFS�ļ�����
	 * @param hdfsfile 	hadoop�е��ļ�
	 * @throws Exception
	 */
	public void testRead(String hdfsfile) throws Exception {
		Configuration conf = new Configuration();
		//���һ����HDFS�ӿڵ�FileSystem����
		FileSystem hdfs=FileSystem.get(URI.create(hdfsfile),conf);
		InputStream in=null;
		in=hdfs.open(new Path(hdfsfile));
		IOUtils.copyBytes(in, System.out, 4096,false);

	}



	/**
	 * ������HDFS�ϵ��û��ļ�
	 * @param hdfsPath    �ļ�����Ŀ¼
	 * @param oldFilename ���ļ���
	 * @param newFilename ���ļ���
	 * @throws Exception
	 */
	public static void rename(String hdfsPath,String oldFilename,String newFilename) throws Exception {

		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsPath),conf);
		Path frpath = new Path(hdfsPath +"/"+ oldFilename);
		Path topath = new Path(hdfsPath +"/"+ newFilename);			
		hdfs.rename(frpath, topath);//����			
		listFiles(hdfs, new Path(hdfsPath));//�鿴�ļ��б�
	}


	// �鿴HDFS�ļ�������޸�ʱ��
	public static void getModifyTime(String hdfsPath) throws Exception {		
		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsPath),conf);
		Path dst = new Path(hdfsPath);
		FileStatus files[] = hdfs.listStatus(dst);
		for (FileStatus file : files) {		
			System.out.println(file.getPath() + "\t"
					+ new Date(file.getModificationTime()));

		}
	}

	// �鿴HDFS�ļ��Ƿ����
	public static void Exists(String hdfsFile) throws Exception {

		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsFile),conf);
		Path hdfsPath = new Path(hdfsFile);
		boolean ok = hdfs.exists(hdfsPath);
		System.out.println(ok ? "�ļ�����" : "�ļ�������");
	}

	// �鿴ĳ���ļ���HDFS��Ⱥ��λ��
	public static void fileBlockLocation(String hdfsFile) throws Exception {

		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsFile),conf);
		Path dst = new Path(hdfsFile);
		FileStatus fileStatus = hdfs.getFileStatus(dst);
		BlockLocation[] blockLocations = hdfs.getFileBlockLocations(fileStatus,
				0, fileStatus.getLen());
		for (BlockLocation block : blockLocations) {
			System.out.println(Arrays.toString(block.getHosts()) + "\t"
					+ Arrays.toString(block.getNames()));
		}
	}

	// ��ȡHDFS��Ⱥ�����нڵ�����
	public static void getHostName() throws Exception {

		Configuration conf = new Configuration();
		DistributedFileSystem hdfs = (DistributedFileSystem) FileSystem
				.get(URI.create("hdfs://master:9000/"),conf);
		DatanodeInfo[] dataNodeStats = hdfs.getDataNodeStats();

		for (DatanodeInfo dataNode : dataNodeStats) {
			System.out.println(dataNode.getHostName() + "\t"
					+ dataNode.getName());
		}
	}

	/**
	 * �鿴HDFS��ָ��Ŀ¼�µ��ļ��б�
	 * @param hdfs	 �ļ�ϵͳ��ʶ	
	 * @param dir	ָ���鿴��Ŀ¼
	 * @throws IOException
	 */
	public static  void listFiles(FileSystem hdfs,Path dir) throws IOException{

		FileStatus files[] = hdfs.listStatus(dir);
		System.out.println(dir+":");
		for (FileStatus file : files) {
			System.out.println(file.getPath().getName());
		}

	}
	/**
	 * �鿴HDFS��ָ��Ŀ¼�µ��ļ��б�	
	 * @param dir	ָ���鿴��Ŀ¼
	 * @throws IOException
	 */
	public static void listFiles(String dir) throws IOException{		
		Configuration conf = new Configuration();
		FileSystem hdfs=FileSystem.get(URI.create(dir),conf);
		FileStatus files[] = hdfs.listStatus(new Path(dir));
		System.out.println(dir);
		for (FileStatus file : files) {
			System.out.println(file.getPath().getName());
		}
	}

	public static void main(String[] args) throws Exception {
		String split="/";
		String localDirectory="D:/test";
		String localfile="test-2.txt";
		String hdfsDirectory="hdfs://master:9000/user/sunzhifeng/input/";

		//HadoopFile.listFiles(hdfsDirectory);
		HadoopFile.upload(localDirectory+split+localfile, hdfsDirectory);
		// HadoopFile.download(hdfsDirectory+split+"hello.txt", localDirectory);
		// HadoopFile.delete(hdfsDirectory+split+"test-2.txt");
		// HadoopFile.getModifyTime(hdfsDirectory);
		// HadoopFile.fileBlockLocation(hdfsDirectory+split+"hello.txt");
		// HadoopFile.getHostName();
		// HadoopFile.rename(hdfsDirectory+split, "hello.txt", "hello01.txt");

	}
}