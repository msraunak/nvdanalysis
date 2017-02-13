/**
 * List of CWEs used by NIST and available to be chosen in the advanced
 * Vulnerability Search. 
 * @author msr4
 */
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedReader;

public class CweList {

	private ArrayList<CWE> cweList;
	private Set<Integer> nistSet;
	private int[] originalNineteen={16,20,22,59,78,79,89,94,119,134,189,200,255,264,287,310,352,362,399}; 
	private final static String catFileName="cwelist.txt";
	
	/**
	 * Default constructor
	 */
	public CweList(){
		cweList = new ArrayList<CWE>();
		nistSet = new HashSet<Integer>();
		
	}
	
	public void populateList() throws IOException {
		
		BufferedReader bufReader = new BufferedReader(new FileReader(new File(catFileName)));
		String line;
		
		while((line = bufReader.readLine()) != null) {
			addToCweList(line);
			
	     }    
	}
	
	public void addToCweList(String line) {
		
	}
	
	
}
