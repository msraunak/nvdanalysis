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

	private ArrayList<CWE> wknessListAll;
	private ArrayList<CWE> nistList; // The CWEs that were used by NIST (19 of them);
	
	private static Set<Integer> nistSet;
	private static int[] nist19={16,20,22,59,78,79,89,94,119,134,189,200,255,264,287,310,352,362,399}; 

	private final static String catFileName="cwelist.txt";
	
	static {
		nistSet = new HashSet<Integer>();
		for (int i=0; i<nist19.length; i++){
			nistSet.add(new Integer(nist19[i]));
		}
	}
	
	/**
	 * Default constructor
	 */
	public CweList(){
		wknessListAll = new ArrayList<CWE>();
	}
	
	// Getter
	public ArrayList<CWE> getWeaknessList(){
		return wknessListAll;
	}
	
	/**
	 * Check if a particular 
	 * @param cweId
	 * @return
	 */
	public static boolean isPartOfNist19(String cweId){
		Integer id;
		try {
			id = Integer.parseInt(cweId);
			return nistSet.contains(id); // Java will do the autobox autounbox as needed
		} catch (NumberFormatException nfe) {
			return false; // it's either CWE-Other or CWE-noinfo
		}
	}
	/** 
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
		String patternRegEx = "^.*(<option.*CWE-)(.*)(\">)(.*)(</option>).*$";
		String id, name;

	    Pattern pattern = Pattern.compile(patternRegEx);
	    Matcher matcher = pattern.matcher(line);
	    if (matcher.matches()) {
	    	try {
	    		id = matcher.group(2);
	    		name = matcher.group(4);
		    	cwe = new CWE(id, name);
		    	this.wknessListAll.add(cwe); // add it to the weaknessList ArrayList
		    	if (cwe.isOneOfNIST19())
		    		this.nistList.add(cwe);

	    	} catch (NumberFormatException nfe) {
	    		System.out.println(line);
	    		System.exit(1);
	    	}
	    } else {
	        System.out.println("NO MATCH in " + line);
	    } 
	}

	/**
	 * Print the list of CWEs
	 */
	public void printAll(){
		
		for (CWE cwe: wknessListAll){
			System.out.println(cwe);
		}
	}
	
}
