SCRP   =,  M,  ��RIQS   TRAP     ﻿media/script/nut/a3090.nut     mainTRAP                    
      TRAP     main     endfile     sceneTRAP     thisTRAPTRAP     this        	   TRAP             "      �  	   TRAPTRAP          0              0              0          �  TRAPTRAP     media/script/nut/a3090.nut     mainTRAP                           TRAP     PrevPreview           CrntPreview     NextPreview     MainInit     GetCheckReadPreview     scene     endfileTRAP     thisTRAPTRAP     this           TRAP                          
                        TRAPTRAP                                                           �  TRAP     TRAP     media/script/nut/a3090.nut     endfileTRAP             	              TRAP     RegisterCGvar  '   ef3090_体育館スクリーン文字_a     Status     skip_express  
   SetBacklog     从幕后，     null     MojikaGetBackId     a     抬起头――     b     PreGameName     GameName     a3090sl.nut     MainEndTRAP     thisTRAPTRAP     this           TRAP                                                         TRAPTRAP                	     	                                	            	          
   	                                      �  TRAP
     TRAP     media/script/nut/a3090.nut     sceneTRAPR             �       R      TRAP  	   SceneInit     PrintGO  	   上背景     CreateFrame     CreateEyelids     CreateTextureSP     絵効果01     Center     Middle  '   cg/ef/efbg3090_放送室ブース_a.png     RandomShakeStart     PreGameName           CheckRootSkipExpress     Wait  
   FadeDelete  	   TypeBegin     Print  �   
//【許斐鳴子】
<voice name='許斐鳴子' class='許斐鳴子' src='voice/a30/9000010a05'>
『第一学期期末典礼正式开始』
     TextBoxDelete  1   
讲台边的播音角传出许斐的声音。
  %   
我可以自由进出广播部。
  +   
现在开始，逼出笑子的真身。
  �   
//【許斐鳴子】
<voice name='許斐鳴子' class='許斐鳴子' src='voice/a30/9000020a05'>
『接下来有请名誉校长演讲。名誉校长，请致辞』
     CreateSE     SE01     se物体_ライト_消える  
   MusicStart     CreateColorEX     絵色黒00     BLACK     Fade     SE02  #   se物体_プロジェクタ_起動L  7   
体育馆里的灯光暗下，投影仪启动了。
  (   
屏幕上投影出巨大的人影。
     
是来自东京的转播。
  s   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000030b02'>
『咳！』
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000040b02'>
『我是名誉校长，许斐永业』
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000050b02'>
『酷暑当头，树望学院的诸位同学过得还好吗』
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000060b02'>
『我们私立树望学院，是省内最好的学校』
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000070b02'>
『肩负家乡未来的诸位，现在可以说正处于人生的十字路口』
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000080b02'>
『跨越这道难关，未来就是康庄大道』
     
领导还在讲话。
  "   
大部分学生都没听吧。
  1   
但是整个学校的学生现在都在场。
     
这是个绝佳的机会。
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000090b02'>
『此时此刻，我想将这句金玉名言赠与大家』
  �   
//【許斐永業】
<voice name='許斐永業' class='許斐永業' src='voice/a30/9000100b02'>
『读书百遍，其义自见——』
     SetVolumeEX  	   絵色黒     Scale     Axl1     Delete     se人体_動作_衣擦れ01  C   
我拨弄了两下调音台，急匆匆地赶往讲台幕后。
     SE99  (   se環境_ガヤ_体育館ざわめき01L     CreateCameraOrtho     カメラ01     SCREEN_WIDTH     SCREEN_HEIGHT     RandomShakeStart3D  0   cg/ef/efbg3092_学園体育ステージ袖_a.png     Move3D  	   SetCamera     SE88  "   
噪音响彻整个体育馆。
     
东京的转播中止了。
  (   
取而代之出现在屏幕上的，
     CreateTextureEX     絵効果02  1   cg/ef/ef3090_体育館スクリーン文字_a.png     RegisterCGvar  '   ef3090_体育館スクリーン文字_a  5   
#{・・・・・・・}我是真正的笑子#。
     
是我布下的陷阱。
  +   
笑子看到这个肯定会有反应。
     
接下来要做的只有，
     
从幕后，
     
抬起头——
     SceneEndTRAP     thisTRAPTRAP     this        Q  TRAP"       $       (      )      *      +   
   ,      -      .      0      1      3   %   C   (   D   +   I   /   L   3   M   6   P   :   S   >   T   A   W   E   Z   I   [   L   ^   P   `   T   d   W   e   Z   j   ^   l   b   n   e   o   h   p   m   q   p   r   u   s   |   t      v   �   y   �   z   �   }   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �     �     �   
  �     �     �     �     �     �      �   $  �   (  �   +  �   /  �   3     9    >    G    N    Q    T    W    \    _    b    f    j    m    v    y    �    �    �    �    �     �  !  �  #  �  $  �  '  �  (  �  +  �  .  �  /  �  2  �  5  �  6  �  9  �  ;  �  =  �  >  �  ?  �  A  �  D  �  E  �  H  �  L    M    P  
  S    T    W    [    \    _     a  $  f  *  g  -  j  1  m  5  n  8  q  <  t  @  u  F  w  L  }  O  ~  Q  TRAPTRAP                  N                              �       	     	  	        
               	     �   ,           
                  �                �                     �                        
                 ,                                              ,                                              ,                             (                 ,                �                        2                 ,                �                                 �           d                 �       	              �    �                         !             �    �          �            	         �                        <     "            ,                             F     #            ,                             H     $            ,                �                        P     %            ,                             Z     &            ,                             d     '            ,                             n     (            ,                             x     )            ,                             �     *            ,                             �     +            ,                             �     ,            ,                             �     -            ,                             �     .            ,                             �     /            ,                             �     0            ,            1          �    �                2     �       	     3         �    L    L    4   	            	         2     �    �                 5            5                   6                  �           �                        �     7            ,                8   9       8     �    �          �            	         �       :    ;                 �       -  <   	  =   	     	  �  
     	>    ;                 
        	  �       -  ?        3               @    @                  	     @                             +              +
        -          	      
     	A       ;   1    B     �    �                2     �                 1          �    �                �                        �     C            ,                             �     D            ,                             �     E            ,                �       F    G     �       	     	  H            G     �     �                       I    J            �                        �     K            ,                                 L            ,                                 M            ,                                 N            ,                G     �                                  "    O            ,                             ,    P            ,            1          �                  1    8     �                      �       Q           �  TRAP          LIAT    