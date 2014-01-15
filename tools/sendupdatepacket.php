<?php

$host = "localhost";
$port = 5347;

$userbindname = "cron";
$userlogin = "routeruser_cron";
$userpassword = "secret";
$service = 'jabberd-router';


set_time_limit(0);


print ("Connecting\n");
$socket = socket_create(AF_INET, SOCK_STREAM, 0) or die("Could not create socket\n");
socket_connect( $socket, $host, $port );
  
$parser = xml_parser_create_ns();
xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, false); 
 
$state = 'Header1';
$staterecieving = false;

while(true)
{
  if($staterecieving)
  {
    $buffer = socket_read($socket,1);
    $result = xml_parse($parser, $buffer, false);
    if($result == 0)
    {
      print("[" . xml_get_current_line_number($parser) . "," . xml_get_current_column_number($parser) . "]" . xml_error_string(xml_get_error_code($parser)));
      $state = 'Finished';
      $staterecieving = false;
    }      
  }
  
  switch($state)
  {
    case 'Header1':
    {  
      print ("Sending headers\n");

      $xmlheader = "<?xml version=\"1.0\"?>";
      $streamheader = "<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\" >";

      socket_write($socket, $xmlheader, strlen ($xmlheader));
      socket_write($socket, $streamheader, strlen ($streamheader));
      
      $state = 'Header2';
      $staterecieving = true;
      function Handler_Features_End($parser, $name)
      {
	global $state;
	global $staterecieving;
	if($name == 'http://etherx.jabber.org/streams:features')
	{
	  print ("\nrecieved features\n");
	  $state = 'Header3';
	  $staterecieving = false;	
	}
      };
      xml_set_element_handler( $parser, Null, 'Handler_Features_End' );
      xml_set_character_data_handler( $parser, Null );
      break;
    }
    case 'Header3':
    {  

      $auth = "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" mechanism=\"DIGEST-MD5\"/>";
      
      print ("Sending auth request\n");
      
      socket_write($socket, $auth, strlen ($auth));      
      
      $state = 'Header4';
      $staterecieving = true;
      $challengedata = '';
      $inchallengedata = false;
      
      function Handler_Challenge_Contents($parser, $data)
      {
	global $challengedata;
	global $inchallengedata;
	if($inchallengedata)
	  $challengedata = $challengedata . $data;
      };
      function Handler_Challenge_Start($parser, $name)
      {
	global $inchallengedata;
	if($name == 'urn:ietf:params:xml:ns:xmpp-sasl:challenge')
	{
	  $inchallengedata = true;  
	}
      };
      function Handler_Challenge_End($parser, $name)
      {
	global $state;
	global $staterecieving;
	global $challengedata;
	global $inchallengedata;
	if($name == 'urn:ietf:params:xml:ns:xmpp-sasl:challenge')
	{
	  print ("\nChallenge recieved : ".base64_decode($challengedata)."\n");
	  $inchallengedata = false;
	  $state = 'Header5';
	  $staterecieving = false;	  
	}
      };
      xml_set_element_handler( $parser, 'Handler_Challenge_Start', 'Handler_Challenge_End' );
      xml_set_character_data_handler( $parser, 'Handler_Challenge_Contents' );
      break;
    }
    
    
    case 'Header5':
    {      
      $decodedchallengedata = base64_decode($challengedata);
      preg_match('/realm="(?P<realm>[^"]*)", nonce="(?P<nonce>[^"]*)"/', $decodedchallengedata, $matches);
      
      $realm = $matches['realm'];
      $nonce = $matches['nonce'];
      $cnonce = base64_encode(md5(rand()));
      $resource = 'myResource';
      $digesturi = $service."/".$host;
      $nc="00000001";
      $qop="auth";
    
      $X = $userlogin.":".$realm.":".$userpassword;
      $Y = pack('H32', md5($X));
      $A1 = $Y.":".$nonce.":".$cnonce;
      $A2 = "AUTHENTICATE:".$digesturi;      
      $HA1 = md5($A1);      
      $HA2 = md5($A2);   
      $KD = $HA1.":".$nonce.":".$nc.":".$cnonce.":".$qop.":".$HA2;
      $response = md5($KD);     
      
      $authtoken = "username=\"$userlogin\", realm=\"$realm\", nonce=\"$nonce\", cnonce=\"$cnonce\", nc=$nc, qop=$qop, digest-uri=\"$digesturi\", response=\"$response\", charset=utf-8" ;
               
      $auth1 = "<response xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">";
      $auth2 = base64_encode($authtoken);
      $auth3 = "</response>";
    
      print ("Sending challenge response : ". $authtoken ."\n");
    
      socket_write($socket, $auth1, strlen ($auth1));  
      socket_write($socket, $auth2, strlen ($auth2));  
      socket_write($socket, $auth3, strlen ($auth3));    
    
      $state = 'Header6';
      $staterecieving = true;
      
      function Handler_AuthSuccess_End($parser, $name)
      {
	global $state;
	global $staterecieving;
	global $challengedata;
	global $inchallengedata;
	if($name == 'urn:ietf:params:xml:ns:xmpp-sasl:success')
	{
	  print ("Auth OK ! \n");
	  $state = 'Header7';
	  $staterecieving = false;	  
	}
      };
      xml_set_element_handler( $parser, Null, 'Handler_AuthSuccess_End' );
      xml_set_character_data_handler( $parser, Null );
      
      break;
    }
    
    case 'Header7':
    {      
      // reset parsing
      xml_parser_free($parser);	  
      $parser = xml_parser_create_ns();
      xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, false);     
      $state = 'AuthedHeader1';
      $staterecieving = false;	 
      break;
    }
    
    case 'AuthedHeader1':
    {  
      print ("Sending Authed headers\n");

      $xmlheader = "<?xml version=\"1.0\"?>";
      $streamheader = "<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\" >";

      socket_write($socket, $xmlheader, strlen ($xmlheader));
      socket_write($socket, $streamheader, strlen ($streamheader));
      
      $state = 'AuthedHeader2';
      $staterecieving = true;
      function Handler_AuthedFeatures_End($parser, $name)
      {
	global $state;
	global $staterecieving;
	if($name == 'http://etherx.jabber.org/streams:features')
	{
	  print ("\nrecieved features\n");
	  $state = 'AuthedHeader3';
	  $staterecieving = false;	
	}
      };
      xml_set_element_handler( $parser, Null, 'Handler_AuthedFeatures_End' );
      xml_set_character_data_handler( $parser, Null );
      break;
    }
    case 'AuthedHeader3':
    {
      $bind = "<bind xmlns=\"http://jabberd.jabberstudio.org/ns/component/1.0\" name=\"$userbindname\"/>";
      print ("Sending bind request : $bind\n");
      socket_write($socket, $bind, strlen ($bind));
      
      $state = 'AuthedHeader4';
      $staterecieving = true;
      function Handler_Bind_End($parser, $name)
      {
	global $state;
	global $staterecieving;
	if($name == 'http://jabberd.jabberstudio.org/ns/component/1.0:bind')
	{
	  print ("\nBind ok\n");
	  $state = 'Running';
	  $staterecieving = false;	
	}
      };
      xml_set_element_handler( $parser, Null, 'Handler_Bind_End' );
      xml_set_character_data_handler( $parser, Null );
      break;  
    }    
    case 'Listening' :
    {  
      $state = 'Listening';
      $staterecieving = true;
      xml_set_element_handler( $parser, Null, Null );
      xml_set_character_data_handler( $parser, Null );
      break; 
    } 
    case 'Running' :
    {  
      $packet = "<route xmlns=\"http://jabberd.jabberstudio.org/ns/component/1.0\" from=\"$userbindname\" to=\"sm\"><iq xmlns=\"jabber:client\" from=\"$userbindname\" to=\"sm\" type=\"get\"><query xmlns=\"jabber:iq:rostercustom:applydbchanges\"/></iq></route>";
      
      
      print ("Sending packet : $packet \n");
      socket_write($socket, $packet, strlen ($packet));
      sleep(5);
      
      //$buffer=socket_read($socket,1024);
      //print ("\n".$buffer."\n");
      
      $state = 'Running';
      $staterecieving = false;
      xml_set_element_handler( $parser, Null, Null );
      xml_set_character_data_handler( $parser, Null );
      break;
    } 
  }
  
  if($state == 'Finished')
    break;
}

xml_parser_free($parser);

// close sockets 
socket_close($socket);

?>
