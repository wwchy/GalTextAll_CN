SCRP   *m  :m  úúRIQS   TRAP     media/script/nut/e4010.nut     mainTRAP                    
      TRAP     main     endfile     sceneTRAP     thisTRAPTRAP     this        	   TRAP                   z  	   TRAPTRAP          0              0              0          ÿ  TRAPTRAP     media/script/nut/e4010.nut     mainTRAP                           TRAP     PrevPreview           CrntPreview     NextPreview     MainInit     GetCheckReadPreview     scene     endfileTRAP     thisTRAPTRAP     this           TRAP                          
                        TRAPTRAP                                                           ÿ  TRAP     TRAP     media/script/nut/e4010.nut     endfileTRAP                           TRAP     RegisterCGvar     ef4010_æ¤¿ã®æãåã_a     PreGameName     GameName  	   e4020.nut     MainEndTRAP     thisTRAPTRAP     this        
   TRAP                                   
   TRAPTRAP                                           ÿ  TRAP     TRAP     media/script/nut/e4010.nut     sceneTRAPÅ             °      [      TRAP  	   SceneInit     PreGameName           CheckRootSkipExpress     PrintGO  	   ä¸èæ¯     CreateFrame     CreateEyelids     CreateCameraOrtho     ã«ã¡ã©01     RandomShakeStart3D     CreateTextureSP     çµµå¹æ50     cg/ev/eva3150æ¤¿çãè´_a.png  	   SetCamera     Move3D     CreateSubSP     çµµå¹æ49  1   cg/ef/ef4090_ç¸å¯¾ããã³ã³ã»ã¤ãµã_a.png     BLEND_MODE_NORMAL     AxlDxl1d     CreateDisplacementMapSurface  
   çµµdispsuf     CreateSprite     çµµå     SCREEN     SetDisplacementMap     çµµdisp     Center     Middle     cg/disp/æ°´çæ¨¡æ§disp01.png  
   SetSurface     Rotate     Scale     Scroll     Linear     RandomShake     repeat     Fade     CreateSE     SE98     seç©ä½_è§¦æ_è ¢ãL     SE99      seç©ä½_è§¦æ_ããã¿ã¤ãL  
   MusicStart  	   CreateBGV     Voiceloop01     voice/a31/5000010a04ex     è±æ¤¿  	   VoicePlay  
   FadeDelete     Wait  	   SoundPlay     bgm010  	   TypeBegin     Print  V   
//ãç¨®å´æ¨ã
ããããããããããããããã£ã£ï¼ï¼ï¼ï¼ã
     TextBoxDelete     CreateColorEX     è²é»     BLACK     BgCopy     SetDirectionalBlur     AxlDxl1     SE02     seäººä½_åä½_è¡£æ¦ã02  	   SetStream     Dxl1d     Dxl2d     Axl1d     Delete     çµµ*  $   cg/ef/efbg4010_å¥¥ã®é¢åºå£_a.png     SE01     seäººä½_åä½_é¡ãä¸ãã     SetVolumeEX     SE9*     RandomShakeStart  1   
ããã£ããã®æå¿ã§é¡ãé¸ããï¼
     
æ¶ããï¼
  4   
è¦çããã³ã³ã»ã¤ãµããé¤å¤ããï¼
     
ãã®èª¿å­ã ï¼
     
æ­£æ°ã«ãªãï¼
     
éããï¼
     
æ­»ã¬ï¼
  .   
ä»ããããããå»ããªãã¨ââ
  g   
//ãè±æ¤¿ã
<voice name='è±æ¤¿' class='è±æ¤¿' src='voice/e40/1000010a04'>
ãç¨®å´â¦â¦ã
     seç©ä½_é´_é³´ã  	   çµµè²ç½     WHITE  
   
ãã
     
ãããã
     
ããã ã£ãã®ãã
     DeleteBg     seç¹æ®_æ¬é³_åæ³02     CreateCamera     ã«ã¡ã©02     SCREEN_WIDTH     tofloat     SCREEN_HEIGHT     XBg01A2  3   cg/ef/efbg1030_å¥³å­æ´è¡£å®¤ã­ãã«ã¼å_b.png     XBg01B  3   cg/ef/efbg1030_å¥³å­æ´è¡£å®¤ã­ãã«ã¼å_c.png     XBg01C  3   cg/ef/efbg1030_å¥³å­æ´è¡£å®¤ã­ãã«ã¼å_e.png     SetShadingPower     SHADE_LEVE_LOW     SetColorGlow  =   
ã­ãã«ã¼ã«é ãã¦ããåãè¦éããã®ã¯ã
  /   cg/ep/sl/xbg502010_30_é­æ­£ç¥ç¤¾ç¸å´_b2.png     çµµå¹æ01  0   cg/ep/a1082/epeve4102æ¤¿ãã¥ã¼ä¸äººç§°_a.png  	   SetCenter     Dxl1  @   
å·ã«æµããæ­»ã«ããã¦ããåãæã£ãã®ã¯ã
  	   çµµè²é»     
è±æ¤¿ã ã
     seäººä½_åä½_è¡£æ¦ã04  %   cg/ef/ef4010_æ¤¿ã®æãåã_a.png     RegisterCGvar     ef4010_æ¤¿ã®æãåã_a     seç©ä½_è§¦æ_ã¬ãã  )   
//ãç¨®å´æ¨ã
ãæ¥ããï¼ã
     
å½¼å¥³ã®æãæ´ãã ã
     SE03  1   
è¿½ãç¸ãè§¦æããå¼ãã¯ãããã
     Axl1     seäººä½_è¡æ_è»¢å03     Bg  #   bg507010_30_é­æ­£ç¥ç¤¾å¥¥ã®é¢_a     
è»¢åã
     
æã®ã²ããæ»ãã
  "   
ä½æ¶²ã«ã¾ã¿ãã¦ããã
     
ä¸æãæ´ããªãã
  "   
é£ãåºããã¨ãªãã¦ã
  p   
//ãè±æ¤¿ã
<voice name='è±æ¤¿' class='è±æ¤¿' src='voice/e40/1000020a04'>
ããé¡â¦â¦ãâ¦â¦ã
     
è¦ããªã
     
è¦ã¡ããã¡ã ã
     
å¸ãè¾¼ã¾ããã
  (   
ææãåãä¸¸åã¿ã«ããã
  .   
åã¯å½¼å¥³ããè¦ç·ãé¸ããã¦ã
     
å¾ãæãä¼¸ã°ããã
     seäººä½_åä½_è¡£æ¦ã01  &   
//ãç¨®å´æ¨ã
ãæ´ãï¼ã
     seäººä½_åä½_æ´ã     CreateTextureEX  +   
æ»ããªãããã«ãã£ããã¨ã
  .   
ãäºãããäºãã®æé¦ãæ´ãã
  ,   
//ãç¨®å´æ¨ã
ããµãã£ï¼ï¼ã
  %   
æ¨ã®åºã¯ç²æ¶²ã¾ã¿ãã ã
  %   
åãå¸ãåããã¦ããã
  .   
èå¾ããã¯å¨ã¦ãåã¿è¾¼ãé³ã
     seç©ä½_è§¦æ_ãã­ã     
è§¦æãè¿½ãç¸ãã
  %   
ç²èãå¨ã¦ãæ¶åããã
  +   
å¼ããããã¾ãããçµããã
     
ã¾ããçµããã
     çµµå¹æ48  ;   
//ãç¨®å´æ¨ã
ãããããããã£ã£ï¼ï¼ã
     çµµå¹æ47     
æ¥ãï¼
     çµµå¹æ46     çµµå¹æ45     
ãã¨å°ãââ
     seç©ä½_è§¦æ_è¦ã     
åã®åè¡¡ãç ´ããã
     SE04     seäººä½_è¡æ_è»¢å01     Move     Axl2     SE05  &   
//ãç¨®å´æ¨ã
ããã£ï¼ã
  p   
//ãè±æ¤¿ã
<voice name='è±æ¤¿' class='è±æ¤¿' src='voice/e40/1000030a04'>
ããâ¦â¦ç¨®å´â¦â¦ã
     
å©ãã£ãï¼
     
ããã¾ã ã ã
  .   cg/ef/ef4010_æ¤¿ãæ±ãããããæ¨_a.png  .   
è±ã¯ã¾ãã§ç³¸ã®åããäººå½¢ã ã
  .   
éåã«è² ãã¦å´©ãè½ã¡ãã¾ã¾ã
  (   
èªéãæ¯ããåãããªãã
  )   
//ãç¨®å´æ¨ã
ãç«ã¦ãï¼ã
  g   
//ãè±æ¤¿ã
<voice name='è±æ¤¿' class='è±æ¤¿' src='voice/e40/1000040a04'>
ãç¡çâ¦â¦ã
  2   
//ãç¨®å´æ¨ã
ãç¡çãããªãï¼ã
     
åã¯å«ãã ã
  +   
å«ã°ãã«ã¯ããããªãã£ãã
  8   
//ãç¨®å´æ¨ã
ãæ­»ãªãã¦ãã¾ããï¼ã
     
æ±ããã
     
æ¯ããã
     
èµ°ãã
     
é£ãåºãã
  "   seäººä½_è¶³é³_ããããè¸ã      bg505010_30_é­æ­£ç¥ç¤¾å±±é_a     seäººä½_è¶³é³_èµ°ãåL     
éããã
  #   
#{ã»ã»ã»ã»}ä»åº¦ãã#ã
  %   
åãã¡ã¯éãåããã ï¼
     SceneEndTRAP     thisTRAPTRAP     this        Z  TRAP              "      #   	   $      %      '      (      *      +   '   ,   *   -   6   .   G   /   J   0   V   2   a   3   f   4   m   5   p   6   w   7   z   8      9      :      ;      =   ¦   >   ©   ?   ¬   @   µ   B   ¾   C   Â   D   Ê   E   Ñ   I   Ñ   X   Ô   [   Ù   \   Ü   `   à   b   ä   c   é   d   ð   f   ú   g   ý   h     j     k     l     m     n   "  o   (  p   /  q   8  s   D  u   J  v   M  w   Q  y   V  {   \  |   b  }   e     h     k     o     s     v     z     ~                                     ¡     ¤     ¥   ¢  ¨   ¦  «   ª  ¬   ­  ¯   ±  ²   µ  ³   ¸  ¶   ¼  ¹   À  ¼   Æ  ½   Ì  À   Ï  Á   Ò  Æ   Ö  È   Ú  É   à  Ë   ã  Ì   æ  Î   ë  Ï   ð  Ñ   ø  Ø   û  Û   þ  Ü     ß     â   	  ã     æ     é     ê     í     ð     ñ   "  ô   &  ö   *  ù   ,  ú   /  ü   4  þ   E  ÿ   M     V    Y    a    j    m    u    ~  	    
                      ¡    ¥    ©    ¬    ±    ¶    ¾  !  Â  #  É  $  Ô  %  ×  &  ß  '  ë  )  î  *  ö  +    ,    -    .    0  #  3  &  6  ,  7  /  :  3  <  7  =  <  >  C  @  G  C  J  D  M  G  Q  I  U  K  [  M  ^  N  a  P  f  Q  m  R  v  S    T    V    W    Y    Z    ]     ^  £  b  §  e  «  f  ®  i  ²  k  ¶  l  ¹  m  ¾  p  Ç  q  Ê  t  Î  v  Ò  x  Û  y  Þ  {  ã  |  ê  }  ï  ~  ø    ÿ        	            %    2    8    ;    ?    C    F    J    N    Q    U     Y  ¡  \  ¤  `  §  d  ¨  g  «  k  ­  o  °  r  ±  u  ¶  y  ¸  }  »    ¼    ¿    Â    Ã    Æ    É    Ê    Í     Ð  ¤  Ñ  §  Ô  «  ×  ¯  Ø  ²  Û  ¶  Þ  º  ß  ½  â  Á  ä  Å  å  È  è  Í  é  Ð  í  Ô  ï  Ø  ð  Û  ò  à  ó  ç  ô  ð  õ  ý  ø    ù    ü    ÿ                       "    (    +    /    3    6    :    >    A    E  !  I  "  L  %  P  '  T  (  W  +  \  ,  _  /  c  3  g  4  j  7  n  ;  r  <  u  ?  y  B  }  C    F    H    I    K    L    M     P  ¦  Q  ©  U  ­  W  ±  X  ¸  Y  Á  \  Ç  ]  Ê  `  Î  b  Ò  c  Ù  d  â  g  è  h  ë  k  ï  m  ó  n  ú  o    r  	  s    v    x    y    z    |  "  ~  +    0    9    @    F    I    L    P    T    W    \    e    o    y                    ¢    §    °    ³  £  ·  ¦  »  §  ¾  ¬  Â  ¯  Æ  °  É  ³  Í  ¶  Ñ  ·  Ô  º  Ø  ¼  Ü  ½  ß  ¿  ä  À  ë  Á  ô  Â  ÿ  Ã  	  Å    Ç    È    Ë    Ì    Ï    Ò  #  Ó  &  Ö  *  Ù  .  Ú  1  Ý  5  á  9  â  <  æ  @  é  D  ê  G  ï  K  ò  O  ó  R  ÷  V  ú  Z  û  ]  þ  a    e    h    l  	  p  
  s    w    {    ~                        ¨    ±    ¸    ¿  !  Â  "  Å  %  É  (  Í  )  Ð  ,  Ô  /  Ø  0  Û  3  ß  6  ã  7  æ  :  ê  ?  î  @  ñ  A  ö  B  û  C    D    E  
  G    H    I    J    K     M  &  P  ,  Q  /  T  3  W  7  X  :  [  >  ^  B  _  E  b  I  e  M  f  P  i  T  w  X  x  Z  TRAPTRAP           	     ÿ   ,           
  È               N                         	                            Ð        	  è  
     	
    	                 ô    
        -  Â       -                 	                                +              +ô       -              ô    
        -  À       -               	    
  þ       	       è                    	                                +              +ô       -         	                                    +   	      	              d     d                 õ                                           
        	     	                                                ´        !               â           "                          #   	           $         Ð                           	     
                  %             <    &               ,                 '    (   )   '    *   +   ,    (     è    è          è            	     ,    *     è    è          è            	     -    .   /0        1    .           ,               è       2         è                        3    è       4    5           ô       6             7    
     8        9    ,            :    ;     è    <   	         =     õ                        >    =     ô          Z           è    ?   		      
     	'    @   A   B    @     d        ,    @           ¼       &         ,          C   	               	     ,          È                   +D   	      	     &    ;     ,    è    E   	           3    ,       F    G        F    =                 ô       	     	  H        !               ü    ü                  	     $         ô                             	     
                2    ;     È     E   	           '    I   J   B    I     æ        ,    I           °       K    .     è                  K    L     '    ,            3    ô       M            6             7         N        9    ,            6             7         O        9    ,            6             7          P        9    ,            6             7    "     Q        9    ,            6             7    (     R        9    ,            6             7    2     S        9    ,            6             7    <     T        9    ,            6             7    F     U        9    ,            K    5     ô                 K    L     è    ¼            3    è       6             7    P     V        9    ,            K    L     ô                  3    ô       '    I   W   ,    I           Ü       :    X     4    Y   	     &    X     ô    è                       F            3    Ð       6             7    Z     Z        9    ,            6             7    \     Z        9    ,            6             7    ^     [        9    ,            6             7    `     \        9    ,            ]       '    @   ^   ,    @           ¼       _    `           ¼            -  -     a   	  b   	   	c   		  b   		
	   	
	   /   	     
     	    d             	  è       -  e        !    d           ¼    ¼                  	         d   `       f     	        	  è       -  g        !    f           ¼    ¼                  	         f   `       h     
        	  î       -  i        j    h     è    è    k   	  d              	     l    h           È     #   	                !    h           ¼    ¼                  	         h   `   3    è       2    X     ô                 3    è       6             7    n     m        9    ,            '    @   ^   ,    @           ¼       :    X     4    Y   	     &    X     ô    è                                 N           =            	     	              	           ª    è       -  a   	  c   	     	     
     	
    	            f     
        	  ~       -  n            f                         +              +
        -         f   	       o         Â    ª        -  p             o                       2        -          	      
     	q    o     è           !    o           ¸    ¸                  	          o                               -  r   	      	      
     	!    =           L    L    r   	            	     3    ô       2         ô                 6             7    x     s        9    ,            :    t     Ð    <   	     &    t     è    è                                 3    ô       6             7         u        9    ,            K    5     è    ô            3    ô       '    I   v   ,    I           °                ê       	     	  w        !                                     	     $         ô                          2   	     
                      2         ô    r   	          x    y        '    @   z   ,    @           °       '    *   +   ,    *           è          è            	     6             7         {        9    ,            6             7         |        9    ,            '    }   z   ,    }           è       !         È     8    8    r   	           	     6             7          ~        9    ,            !         ,    x    x       	            	     '    @      ,    @           °           =     ç       	     	          :    t     Ð    <   	     j    =     ô    è    k   	  d     r   	      	     &    t     È     è                 2                                   P        !    =           °    °                  	          =                                    	      
     	j    =     ¸          k   	  d     r   	      	     $    =                                   	     
                      2    t     ,    r   	          6             7    ª             9    ,            6             7    ´             9    ,            6             7    µ             9    ,            6             7    ¶             9    ,            6             7    ¸             9    ,            3    ô       6             7    ¾             9    ,            K    *         ¼            6             7    È             9    ,            6             7    Ò             9    ,            6             7    Ü             9    ,            6             7    Þ             9    ,            6             7    æ             9    ,            6             7    ð             9    ,            '    I      ,    I           °       6             7    ú             9    ,            '    @      ,    @                           L       	     	  w        !                                     	     $         ô                          2   	     
                      &         È     è                 6             7                9    ,            6             7                9    ,            '    @   z   ,    @           ¼       K    *     ¸                6             7                9    ,            6             7    "            9    ,            6             7    $            9    ,            6             7    ,            9    ,            '    I      ,    I           è       6             7    .            9    ,            6             7    6            9    ,            6             7    @            9    ,            6             7    J            9    ,            '    I   v   ,    I           °                B       	     	  w        !               L    L                  	     2         ,                  6             7    T            9    ,                      8       	     	  w        !                °    °                  	     2         ,                  6             7    ^    ¡        9    ,                ¢     .       	     	  w        !    ¢           F    F                  	     2          ,                  6             7    `    ¡        9    ,                £     $       	     	  w        !    £                                 	     2    ¢     ,                  6             7    b    ¤        9    ,            '    }   ¥   ,    }           Ü       K    *     Ð    ,            !    £     ,    ¤    ¤       	            	     :    t     Ð    <   	     j    =     ô    è    k   	  d     r   	      	     &    t     È     è                 2    £                        3    è       6             7    h    ¦        9    ,            '    §   ¨   ,    §           °       !    =           @    @                  	          =                                    	      
     	©    =                 s        -                	     j    =           è    k   	  d     r   	      	     $    =     Ü                             	     
                      ©    =         
        -  d     ª   	            	     2    t     ô                 '    «   A   ,    «                  j    =                k   	  d     r   	      	     6             7    |    ¬        9    ,            6             7        ­        9    ,            6             7    r    ®        9    ,            6             7    t    ¯        9    ,            '    I      ,    I           °                °       	     	  °        !               Ð    Ð                  	     ©               r       -  ,       -                	                                              	      
     	M            &         È     è                 ]       F    =        6             7    Ì    ±        9    ,            6             7    Ö    ²        9    ,            6             7    à    ³        9    ,            6             7        ´        9    ,            6             7        µ        9    ,            6             7    ¤    ¶        9    ,            6             7    ®    ·        9    ,            6             7    ¸    ¸        9    ,            6             7    Â    ¹        9    ,            '    @   v   ,    @           °       '    I   A   ,    I           °                È       	     	  °        !                                     	     $         ô                          2   	     
                      !         ô    è    è    r   	            	     &         È     è                 &                                  F            6             7    ê    º        9    ,            6             7    ì    »        9    ,            6             7    î    ¼        9    ,            6             7    ð    ½        9    ,            '    I   ¾   ,    I           Ð       :    t     ¸    <   	     K    *     ô                  &    t     ô    è                 ]       F                ¿   d        3    è       '    @   À   ,    @           Ü          ¼            	     2    t     ô                 K    @     è                  6             7    ô    Á        9    ,            6             7    þ    Á        9    ,            6             7        Â        9    ,            6             7        Ã        9    ,            Ä           ÿ  TRAP          LIAT    