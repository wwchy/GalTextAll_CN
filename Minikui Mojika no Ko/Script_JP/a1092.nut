SCRP   &  &  ��RIQS   TRAP     media/script/nut/a1092.nut     mainTRAP                    
      TRAP     main     endfile     sceneTRAP     thisTRAPTRAP     this        	   TRAP                   G  	   TRAPTRAP          0              0              0          �  TRAPTRAP     media/script/nut/a1092.nut     mainTRAP                           TRAP     PrevPreview           CrntPreview     NextPreview     MainInit     GetCheckReadPreview     scene     endfileTRAP     thisTRAPTRAP     this           TRAP                          
                        TRAPTRAP                                                           �  TRAP     TRAP     media/script/nut/a1092.nut     endfileTRAP                           TRAP     RegisterCGvar  !   ef1092_連鶴のシルエット_a     PreGameName     GameName  	   a1100.nut     MainEndTRAP     thisTRAPTRAP     this        
   TRAP                                   
   TRAPTRAP                                           �  TRAP     TRAP     media/script/nut/a1092.nut     sceneTRAPb             �       ]      TRAP  	   SceneInit     PreGameName           CheckRootSkipExpress     PrintGO  	   上背景     CreateFrame     CreateEyelids     CreateCameraOrtho     カメラ01     SCREEN_WIDTH     SCREEN_HEIGHT     RandomShakeStart3D     CreateTextureSP     XBg01A     Center  /   cg/ep/sl/xbg003010_20_学園生徒会室_b1.png     Move3D  	   SetCamera     CloseEye  
   FadeDelete     FaceUpPerformance_DOWN_XYR     SetVolumeEX     SE*     Wait     OpenEye     CreateSE     SE99  #   se環境_自然_ヒグラシ鳴くL  
   MusicStart  	   TypeBegin     Print  (   
顔を上げれば心が視える。
     TextBoxDelete  (   
彼女の言葉が真実か否か。
  +   
決着をつけることができる。
     Dxl1     CreateSprite     BgCopy     Middle     SCREEN     CreateColorEX  	   絵色黒     BLACK     WaitKey     SetShadingPower     SHADE_LEVE_LOW     Fade     SetErase     Delete     X*     
上げられなかった。
     
もう、
     
彼女の醜い顔を、
     
視たくなかった。
     CreateTextureEX     絵効果01     center     middle  +   cg/ef/ef1092_連鶴のシルエット_a.png     Scale     RegisterCGvar  !   ef1092_連鶴のシルエット_a     SE01     se物体_風鈴_鳴る03     Request     Disused  (   
風鈴の上で、鶴が踊った。
     
あれ？
     EfWindChimeRecoIn1     SERC*  .   cg/ef/ef5184_過去一番最初の記憶_a.png     BLEND_MODE_NORMAL     RandomShadeLoop     EfWindChimeRecoIn2     
僕は、
     
前に、
     
どこかで、
     
これを見た？
     EfWindChimeRecoOut1     RandomShadeLoopStop     Bg  ,   bg003020_20_学園生徒会室入り口側_b     Top     CreateFootShadow  *   stfs捨_制服_通常_靴生徒会室_20_b     EfWindChimeRecoOut2  s   
//【許斐鳴子】
<voice name='許斐鳴子' class='許斐鳴子' src='voice/a10/9200010a05'>
「捨？」
     se人体_足音_一歩旧校舎  (   
一刻も早く離れたかった。
     SE02     se物体_ドア旧校舎_開く     DeleteBg  4   
僕は逃げるように生徒会室を出た。
     bgm*     voice*     ClearFadeAll     SceneEndTRAP     thisTRAPTRAP     this        \  TRAP              "      #   	   $      %      &      '      (      )   '   *   6   +   9   ,   =   -   D   4   D   6   G   7   M   B   P   S   T   T   W   _   `   b   c   c   f   f   j   i   n   j   q   m   u   p   y   q   |   t   �   v   �   w   �   x   �   z   �   {   �   }   �   ~   �      �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �      �     �   	  �     �     �     �   #  �   &  �   .  �   1  �   5  �   =  �   A  �   G  �   J  �   M  �   Q  �   U  �   X  �   [  �   _  �   c  �   h  �   n  �   y  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �     �    �    �    �    �    �    �  
  �    �    �    �    �    �                       !    $    &    '    (  "  )  '  *  .  +  0  .  3  /  6  2  :  4  >  =  A  >  G  ?  M  @  S  B  W  D  Z  E  \  TRAPTRAP           	     �   ,           
  ;               N                         	                 �       -  
   	     	     	  �  
     	    	                 
        	  �       -                                       +              +
        -          	      
     	       	                              �                            	                 �                      �           �                               �    �          �            	         �                        
              !    ,                                  "        !    ,                                  #        !    ,                     �    �     $   	     %    &     �       	  '   	  (        )    *     �    +   	     ,    �           �             -    &     �    �    .   	  d     $   	      	     /    *           �                 0    &             1    2                          ,    �                        (     3        !    ,                             2     4        !    ,                             4     5        !    ,                             6     6        !    ,                �                �          $   	     7    8     �    9   	  :   	  ;        -    8     �    �    .   	  d             	     <    8                      =    >            ?   @       ?           �           ,           	     �                  +�       -                +$   	      	      
     	    �       /    8     �    �                       1    	        0    &              /    &     �                              A    &   B            *     �    $   	              �                        P     C        !    ,                �                        Z     D        !    ,            E    �         �	           F     �    
     $   	         8     N       	  '   	  G   H        	  �  
           
%    &     �       	  '   	  (        I    &             J    �                 �                        n     K        !    ,                             p     L        !    ,                             r     M        !    ,                             x     N        !    ,                �       O    �    �           &                         P    &                    Q    R   Sd        T    S     i                   +              +U            8     �                 P    8                   V         ,                          �    �          �            	         �                        �     W        !    ,                �           ?   X       ?           �                                    �     Y        !    ,                Z   [       Z           �       )    *     �    +   	     /    *     �    �                 \           �                        �     ]        !    ,                �           ^     �                           �                      _     �                  `    �                �       a           �  TRAP          LIAT    