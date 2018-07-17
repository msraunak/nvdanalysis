import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;

import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * The main class to drive the program
 * @author msr4
 */

public class CVSSAnalysis {

	
	public static void main (String[] args){
		
		int begYear, endYear;
		begYear=1998;
		endYear=2018;
		String fileName = "NetscapeNumOfVulnByYearAndSeverity.txt";
		String vendor = "netscape";
		String product = "navigator";
		gatherCVSSScoresQuery(begYear, endYear, fileName, vendor, product);
		//Map <Integer, CVECountBySeverity> cvss2 = new TreeMap<Integer, CVECountBySeverity>(); 
		
	
		
	} // end main

	/** Print all vulnerabilities reported year by year 
	 *  @param begYear the beginning year of the data begin printed
	 *  @param endYear the end year of the data being printed
	 */
	public static void printTotalVulnReportedInYear(int begYear, int endYear){
	
		Map <Integer,Integer> totalVulnPerYear = new TreeMap<Integer, Integer>();
		
		for (int year=begYear; year<=endYear; year++){
			totalVulnPerYear.put(year, vulnReportedInAYear(year) );
		}
		
		String strYears="";
		String strVulns="";
		for (Integer yr: totalVulnPerYear.keySet() ) {
			strYears =  strYears+ yr +"\t";
			strVulns = strVulns+ totalVulnPerYear.get(yr) + "\t";
		}
			
		System.out.println(strYears);
		System.out.println(strVulns);
		
	}
	
	/**
	 * Search and find out the number of vulnerabilities reported in a year for a particular CWE type
	 * @param cwe Common Weakness Enumeration
	 * @param year Reporting Year
	 */
	public static void searchByCVSSLevelAndYear(CWE cwe, int year) {
			
	String urlString = "";
		
		urlString += "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cwe_id=CWE-" + cwe.getId(); 
		urlString += "&pub_date_start_month=0&pub_date_start_year=" + year;
		urlString += "&pub_date_end_month=11&pub_date_end_year=" + year;
		
		try {

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);
		    Matcher matcher;
		    
			while (null != (strLine = br.readLine())) {
				
				matcher = pattern.matcher(strLine);	
				if (matcher.matches()){
					int numOfVuln = Integer.parseInt(matcher.group(2).replaceAll(",","")); //strip all commas in the matched gropu
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() 
										+ ": " + cwe.getType() + ": " + year + ":" + numOfVuln);
					
					//cwe.setNumOfVuln(numOfVuln);
					cwe.addNumVulnInYear(year, numOfVuln);
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
			
	}

	/** Given a particular year, find out the total number of vulnerabilities reported in that year
	 * @param year the search year for the number of vulnerabilities 
	 */
	public static int vulnReportedInAYear(int year){
		
		String urlString = "";
		urlString += "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on"; 
		urlString += "&pub_date_start_month=0&pub_date_start_year=" + year;
		urlString += "&pub_date_end_month=11&pub_date_end_year=" + year;
				
		try {
				URL url = new URL(urlString);
				BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
				
				String strLine = "";
				String patternRegEx = "(.*)There are <strong>(.*)</strong> matching records(.*)";
				Pattern pattern = Pattern.compile(patternRegEx);
			    Matcher matcher;
			    
				while (null != (strLine = br.readLine())) {
					
					matcher = pattern.matcher(strLine);	
					if (matcher.matches()){
						int numOfVuln = Integer.parseInt(matcher.group(2).replaceAll(",","")); //strip all commas in the matched gropu
						System.out.println(year + ": " + numOfVuln);
						
						return numOfVuln; 
					}
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}	
		return -1;
	}// end method vulnReportedInAYear
	
	
	/** Collects the CVSSv2 score with their different severities for each year and then prints them 
	 * 
	 * @param begYear the beginning year of the search
	 * @param endYear the end year of the search
	 * @param fileName the name of the file to be written to
	 */
	public static void gatherCVSSScoresByYearRange(int begYear, int endYear, String fileName)
	{
		Map <Integer, CVECountBySeverity> cvssv2 = new TreeMap<Integer, CVECountBySeverity>();
		int low;
		int medium;
		int high;
		int all;
		CVECountBySeverity cve;
		
		for (int year=begYear; year<=endYear; year++)
		{
			// find the number of each severity of CVSSv2 for the given year
			low = searchSeverityCVSSv2(year, "LOW");
			medium = searchSeverityCVSSv2(year, "MEDIUM");
			high = searchSeverityCVSSv2(year, "HIGH");
			all = searchSeverityCVSSv2(year, "ALL");
			cve = new CVECountBySeverity(low, medium, high, all);
			System.out.println("Year: " + year + " Low: " + low + " Medium: " + medium + " High: " + high + " All: " + all);
			cvssv2.put(year, cve);	
		}	
		
		printCVSSv2DataToFile(cvssv2, fileName);
	}//end method gatherCVSSScoresByYearRange
	
	
	/** Collects the CVSSv2 score with their different severities for each year and then prints them 
	 * 
	 * @param begYear the beginning year of the search
	 * @param endYear the end year of the search
	 * @param fileName the name of the file to be written to
	 */
	public static void gatherCVSSScoresQuery(int begYear, int endYear, String fileName, String vendor, String product)
	{
		Map <Integer, CVECountBySeverity> cvssv2 = new TreeMap<Integer, CVECountBySeverity>();
		int low;
		int medium;
		int high;
		int all;
		CVECountBySeverity cve;
		
		for (int year=begYear; year<=endYear; year++)
		{
			// find the number of each severity of CVSSv2 for the given year
			low = searchSeverityQeuryCVSSv2(year, "LOW", vendor, product);
			medium = searchSeverityQeuryCVSSv2(year, "MEDIUM",vendor, product);
			high = searchSeverityQeuryCVSSv2(year, "HIGH",vendor, product);
			all = searchSeverityQeuryCVSSv2(year, "ALL",vendor, product);
			cve = new CVECountBySeverity(low, medium, high, all);
			System.out.println("Year: " + year + " Low: " + low + " Medium: " + medium + " High: " + high + " All: " + all);
			cvssv2.put(year, cve);	
		}	
		
		printCVSSv2DataToFile(cvssv2, fileName);
	}//end method gatherCVSSScoresByYearRange
	
	/** Collects the number of severity type CVSSv2 entries for a given year
	 * 
	 * @param year the year for the query 
	 * @return the amount of severity type CVE entries for a given year
	 */
	public static int searchSeverityQeuryCVSSv2(int year, String severity, String vendor, String product)
	{
		String urlString = "";
		//the different parts of the URL string being concatenated for severity and year
		urlString += "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cpe_vendor=cpe%3A%2F%3A" + vendor;
		urlString += "&cpe_product=cpe%3A%2F%3A%3A" + product;
		if (severity.equals("ALL"))
			urlString += "&cvss_version=2";
		else
			urlString += "&cvss_version=2&cvss_v2_severity=" + severity; 
		urlString += "&pub_start_date=01%2F01%2F" + year;
		urlString += "&pub_end_date=12%2F31%2F" + year;
		
		int numOfSeverity = -1; //set to -1 default value to ensure valid search
		
		try {                                                             

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));//creates a stream for the URLof the CWE with its year
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong(.*)>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);//compiles the string expression into a pattern;exception can be thrown
		    Matcher matcher;//object that performs match operations on a pattern sequence 
		    
			while (null != (strLine = br.readLine())) {//loops through all the lines in a webpage 
				matcher = pattern.matcher(strLine);	//creates a matcher that will match the given input against the pattern 
				
				if (matcher.matches()){//test if the entire region matches against the pattern
					
					numOfSeverity = Integer.parseInt(matcher.group(3).replaceAll(",","")); //strip all commas in the matched group
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		return numOfSeverity;
	}//end method searchSeverityCVSSv2
	
	
	
	/** Collects the number of severity type CVSSv2 entries for a given year
	 * 
	 * @param year the year for the query 
	 * @return the amount of severity type CVE entries for a given year
	 */
	public static int searchSeverityCVSSv2(int year, String severity)
	{
		String urlString = "";
		
		//the different parts of the URL string being concatenated for severity and year
		if (severity.equals("ALL"))
			urlString += "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cvss_version=2";
		else
			urlString += "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cvss_version=2&cvss_v2_severity=" + severity; 
		urlString += "&pub_start_date=01%2F01%2F" + year;
		urlString += "&pub_end_date=12%2F31%2F" + year;
		
		int numOfSeverity = -1; //set to -1 default value to ensure valid search
		
		try {                                                             

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));//creates a stream for the URLof the CWE with its year
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong(.*)>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);//compiles the string expression into a pattern;exception can be thrown
		    Matcher matcher;//object that performs match operations on a pattern sequence 
		    
			while (null != (strLine = br.readLine())) {//loops through all the lines in a webpage 
				matcher = pattern.matcher(strLine);	//creates a matcher that will match the given input against the pattern 
				
				if (matcher.matches()){//test if the entire region matches against the pattern
					
					numOfSeverity = Integer.parseInt(matcher.group(3).replaceAll(",","")); //strip all commas in the matched group
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		return numOfSeverity;
	}//end method searchSeverityCVSSv2
	
	
	/** prints the collected information on the CVSSv2 severity data to a file
	 * @param cvssv2 map of the years and their severity level counts
	 * @param fileName the file the data is to be written to
	 */
	public static void printCVSSv2DataToFile(Map<Integer, CVECountBySeverity> cvssv2, String fileName)
	{
		PrintWriter pw;
		CVECountBySeverity cveCount;
		int low;
		int medium;
		int high;
		int all;
		
		try
		{
			pw = new PrintWriter(new File(fileName));
			for(Map.Entry<Integer, CVECountBySeverity> entry: cvssv2.entrySet())
			{
				cveCount = entry.getValue();
				low = cveCount.getLow();
				medium = cveCount.getMedium();
				high = cveCount.getHigh();
				all = cveCount.getAll();
				pw.println("Year: " + entry.getKey() + " Low Severity Count: " + low + " Medium Severity Count: " + medium + " High Severity Count: " + high + " All Severity Count: " + all);
			}
			pw.close();
		}
		catch (IOException ioe)
		{
			System.out.println(ioe.getMessage());
		} 
	}//end method printCVSSv2DataToFile
	
} // end class
