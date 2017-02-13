/**
 * List of CWEs used by NIST and available to be chosen in the advanced
 * Vulnerability Search. 
 * @author msr4
 */
import java.util.Set;
import java.util.Arrays;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedReader;

public class CweList {

	private ArrayList<CWE> cweList;
	private Set<Integer> nistSet;
	private int[] origNineteen={16,20,22,59,78,79,89,94,119,134,189,200,255,264,287,310,352,362,399}; 

	private final static String catFileName="cwelist.txt";
	
	/**
	 * Default constructor
	 */
	public CweList(){
		cweList = new ArrayList<CWE>();
		
		nistSet = new HashSet<Integer>();
		for (int i=0; i<origNineteen.length; i++){
			nistSet.add(new Integer(origNineteen[i]));
		}
	}
	
	/* 
	 * Read the text file and populate the source text file. 
	 */
	public void populateList() throws IOException {
		
		BufferedReader bufReader = new BufferedReader(new FileReader(new File(catFileName)));
		String line;
		
		while((line = bufReader.readLine()) != null) {
			processAndAddToCweList(line);
		}    
	}

	/*
	 * 	Exmaple Line: <option value="CWE-824">Access of Uninitialized Pointer</option>
	 */
	public void processAndAddToCweList(String line) {
		
		CWE cwe;
		String patternRegEx = "^.*(<option.*CWE-)(.*)(\">)(.*)(option>).*$";
		int id;
		String name;

	    Pattern pattern = Pattern.compile(patternRegEx);
	    Matcher matcher = pattern.matcher(line);
	    if (matcher.matches()) {
	    	id = Integer.parseInt(matcher.group(2));
	    	name = matcher.group(4);
	    	cwe = new CWE(id,matcher.group(4) );
	    }else {
	        System.out.println("NO MATCH in " + line);
	    } 
		
	}
	
	
}
