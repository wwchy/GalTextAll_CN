SCRP   �<  �<  ��RIQS   TRAP     media/script/nut/e4090.nut     mainTRAP                    
      TRAP     main     endfile     sceneTRAP     thisTRAPTRAP     this        	   TRAP             "      �  	   TRAPTRAP          0              0              0          �  TRAPTRAP     media/script/nut/e4090.nut     mainTRAP                    4       TRAP     PrevPreview           CrntPreview     NextPreview     MainInit     GetCheckReadPreview     scene  
   SetBacklog  4   僕は、#{・・}彼女#を、救いたかった。     null     MojikaGetBackId     a  .   僕は、#{・}僕#も、救いたかった。     b  '   あの時は救えなかったから、     c  $   救うために今ここにいて、     d     モジカを使う――     e     endfileTRAP     thisTRAPTRAP     this        3   TRAP                          
                                       #      *      1      3   TRAPTRAP                                                #             		   	
       	               		   	
       	               		   	
       	               		   	
       	               		   	
       	                   �  TRAP
     TRAP     media/script/nut/e4090.nut     endfileTRAP                           TRAP     PreGameName     GameName     e4090sl.nut     MainEndTRAP     thisTRAPTRAP     this           TRAP                                 TRAPTRAP                               �  TRAP     TRAP     media/script/nut/e4090.nut     sceneTRAPv             �       :      TRAP  	   SceneInit     PrintGO  	   上背景     CreateFrame     Bg  $   bg506010_30_魂正神社奥の院前           CreateSE     SE01     se人体_足音_一歩土  
   MusicStart     SE02     se環境_自然_風01     Wait     PreGameName     CheckRootSkipExpress  
   FadeDelete  	   TypeBegin     Print     
黒い森の真ん中、
     TextBoxDelete     
山の天辺が開けた。
  4   
木造の奥の院が立ち塞がっている。
     CreateSprite     BgCopy     Center     Middle     SCREEN     CreateColorEX  	   絵色黒     BLACK     SetShadingPower     SHADE_LEVE_LOW     Dxl1     Fade     SetVolumeEX     SE99     
足取りが鈍る。
  (   
指先が微かに震えている。
  %   
記憶が僕に襲いかかる。
  "   
運命がまとわりつく。
  +   
呪いが身体の芯に染みつく。
  "   se人体_足音_一歩コンクリ     ScaleBg     RotateBg     Request     Disused  %   
引き返せれば楽だろう。
     
希望を無くして、
     
目を閉じて、
     
世界を変えずに。
     DeleteBg  "   se人体_足音_歩く下り石段     CreateTextureSP     絵効果50  %   cg/ef/ef1070_奥の院を開く_a.png  /   
#{・・・・・・}あの時と同じ#。
     se物体_ドア奥の院_開く     絵効果49  %   cg/ef/ef1070_奥の院を開く_b.png  +   se物体_ドア奥の院_開くゆっくり     絵効果48  %   cg/ef/ef1070_奥の院を開く_c.png     Scale  
   Transition     cg/data/slide_06_00_1.png     Delete     SE03     se物体_木床_軋む  #   bg507010_30_魂正神社奥の院_a     Bottom  
   CreateFoot  0   stf捨_制服_ライト照らし_靴奥の院_30     CreateDisplacementMapSurface  
   絵dispsuf     絵写     SetDisplacementMap     絵disp  "   cg/disp/水玉模様disp01half.png  
   SetSurface     Rotate     Scroll     Linear     RandomShake     repeat     se物体_触手_ぬめり     SetFrequency     
そうか。
     
樹望町の呪い。
     
閉ざされた運命。
  7   
翻弄されていたのは椿だけじゃない。
     
僕もだ。
  1   
僕も樹望町の呪縛を受けていて、
  8   
僕は、#{・・}彼女#を、救いたかった。
  2   
僕は、#{・}僕#も、救いたかった。
     CreateEyelids     CreateCameraOrtho     カメラ01     RandomShakeStart3D     CreateSubSP     cg/ev/eva3150椿生け贄_a.png  	   SetCamera     Move3D  1   cg/ef/ef4090_相対するコンセイサマ_a.png     BLEND_MODE_NORMAL     Move     cg/disp/水玉模様disp01.png     SE98     se物体_触手_蠢くL      se物体_触手_からみつくL     SE98ef     se物体_触手_蠢くEL     SE99ef  !   se物体_触手_からみつくEL  +   
あの時は救えなかったから、
  (   
救うために今ここにいて、
     
モジカを使う――
     SceneEndTRAP     thisTRAPTRAP     this        9  TRAP"       $       (      )      *      ,      -      .      /      1      3      4   &   5   -   6   -   :   3   E   6   F   9   I   =   L   A   M   D   P   H   T   L   U   O   X   S   Z   W   [   ^   ]   c   ^   l   _   s   a   v   d   |   e      h   �   k   �   l   �   o   �   r   �   s   �   v   �   y   �   z   �   }   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �      �     �     �     �     �   #  �   *  �   -  �   1  �   5  �   <  �   ?  �   D  �   G  �   N  �   U  �   a  �   h  �   k  �   o  �   s  �   z  �   }  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �   �  �     �     �   
  �     �     �     �   $  �   -  �   8  �   ;    >    A    D    I  	  L  
  P    [    `    g    j    q    t    {    �    �    �    �    �    �    �     �  #  �  $  �  '  �  *  �  +  �  .  �  1  �  2  �  5  �  8  �  9  �  <  �  ?  �  @  �  C  �  F  �  G  �  J  �  L  �  M    O    P    Q    S    X    Y  !  \  %  _  )  `  ,  c  0  f  4  h  7  i  :  k  ?  m  A  n  K  q  N  r  Z  s  ]  u  i  x  v  y  �  {  �  |  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �  �    �    �    �    �    �    �  !  �  %  �  )  �  ,  �  0  �  4  �  7  �  9  TRAPTRAP                  N                     d               	   
               �                 
               �           �          	     �   ,           
                �                                �                     �                        
                 ,                                              ,                                              ,                     �       	     	                   �       	              �    �        	  d     !   	      	     "         �    �                     �       #    $     �                                        %            ,                             (     &            ,                             2     '            ,                             <     (            ,                             F     )            ,                �              *   
               �       +          �    �                 +    �    �    �    !   	           ,                        +              +                   "         �                              -       .        "         �          !   	                           P     /            ,            "         �    �                        *   
               �           �        +          x    x                 +    �    �    �    !   	           ,                        +              +        -                "         �          !   	                           Z     0            ,            "         �    �                        *   
               �           �        +          �    �                 +    �    �    �    !   	           ,                        +              +                   "         �          !   	                           d     1            ,            "         �    �                        *   
               x           �        +          �    �                 +    �    �    �    !   	           ,                        +              +        -                "         �          !   	                           n     2            ,            "         �    �                 3              4   
               �           �        #         �          !   	         �       5    6     �       	     	  7                 �    !   	              �                        x     8            ,                �              9   
               �       5    :     �       	     	  ;            6     �                        <   
               �                �       	     5    =     �       	     	  >            :     �                 "               �                        ?    =     �    L    L                   	     @         �          �    �    A        	     
           
    �       B    =            �           C   D   
    C           �           �           E   F�       G    F     �                  +              +H        I    J     d     d            K     �                        L    K   J       M     
        	     	  N        O    M   J   P    M                       �        ?    M           �    �       Q    M                      R   	           S    M     �                           	     
                  T             <    "    M           A                         U   
               �                �                 V                                      �                        �     W            ,                             �     X            ,                             �     Y            ,                             �     Z            ,                             �     [            ,                             �     \            ,                     �       	     	                   �       	              �    �        	  d     !   	      	     "         �    �                     �       3       B                             �     ]            ,                             �     ^            ,                �              U   
               �       _       `    a                            �        	  �  
     	b    a        c    6     �    
        -  ^    d               	    
  |       
e    6   a   f    6                         +              +�       -     5    :     �    
        -  �       -  g   h        	  �  
           
i    :           (                   +              	     ?    :           �    �       f    6           (     8    �       -     ?    6           �    �       e    :   a   f    :                         +              +�       -         M     
        	     	  j        O    M   J   P    M                       �        ?    M           �    �       Q    M                      R   	           S    M     �                           	     
                  T             <    "    M           ,                          �    !   	              k   l       $   m       n   o       p   q   
    k     �    �          �            	     
    $     �    �          �            	     
    n                      �            	     
    p                      �            	         �                        �     r            ,                             �     s            ,                             �     t            ,                �       u           �  TRAP          LIAT    