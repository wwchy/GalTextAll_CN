SCRP   Y,  i,  ��RIQS   TRAP     ﻿media/script/nut/f5191.nut     mainTRAP                    
      TRAP     main     endfile     sceneTRAP     thisTRAPTRAP     this        	   TRAP             &      �  	   TRAPTRAP          0              0              0          �  TRAPTRAP     media/script/nut/f5191.nut     mainTRAP                           TRAP     PrevPreview           CrntPreview     NextPreview     MainInit     GetCheckReadPreview     scene     endfileTRAP     thisTRAPTRAP     this           TRAP                          
                        TRAPTRAP                                                           �  TRAP     TRAP     media/script/nut/f5191.nut     endfileTRAP                    3       TRAP     RegisterCGvar     ef5191_手に取った風鈴_a     Status     skip_express  
   SetBacklog     「不。不是那样的」     許斐鳴子     voice/f51/9100020a05     MojikaGetBackId     a     心跳加快。     null     b  *   我拼命克制住惊恐尖叫的冲动。     c     她真实的想法，     d  	   是――     e     PreGameName     GameName     f5191sl.nut     MainEndTRAP     thisTRAPTRAP     this        2   TRAP                                               $      +       .   #   0   $   2   TRAPTRAP                	     	          #                   	   	            
             	                         	                         	                         	                                      �  TRAP
     TRAP     media/script/nut/f5191.nut     sceneTRAP^             �       n      TRAP  	   SceneInit     PreGameName           CheckRootSkipExpress     PrintGO  	   上背景     CreateFrame     Bg  #   bg001020_12_学園旧校舎廊下_b     CreateSE     SE98  &   se人体_足音_歩く旧校舎二人L  
   MusicStart  
   FadeDelete     SetVolumeEX     Wait  #   bg002040_12_学園生徒会室前_b     FadeDeletePreBg  	   TypeBegin     Print     
开门。
     TextBoxDelete     SE01     se物体_ドア旧校舎_開く      bg003010_12_学園生徒会室_a     Bottom  
   CreateFoot     stf捨_冬服_通常_靴_12  %   
我度过那个夏天的地方。
  |   
//【許斐鳴子】
<voice name='許斐鳴子' class='許斐鳴子' src='voice/f51/9100010a05'>
「好久没来了」
      
//【種崎捨】
「嗯」
     se人体_動作_衣擦れ01      bg003010_12_学園生徒会室_b  @   
鸣子抬脚，打算先我一步进去，我拦住了她。
  "   
不能让她做危险动作。
  (   se物体_パイプイス_立ち上がる     CreateColorEX  	   絵色黒     BLACK     Fade  %   
我走到窗边，踩上桌子。
     SE02     se人体_動作_触れる  %   
解开绑在窗帘上的绳子，
     SE03     se物体_風鈴_鳴る02     DeleteBg     CreateTextureSP     絵効果50     Center     Middle  (   cg/ef/ef5191_手に取った風鈴_a.png     RegisterCGvar     ef5191_手に取った風鈴_a  7   
摘下成对的纸鹤，和绑在一起的风铃。
  .   
风铃上拙劣地画着丑陋的金鱼。
  .   
玻璃的样子跟金鱼缸一模一样。
  "   
我们就是为它而来的。
  .   
将我们的命运牵连在一起的光。
     
我们能有今天，
     
都多亏了这个风铃。
     se人体_足音_一歩旧校舎  '   stf捨_冬服_通常_靴生徒会室_12     
那么，
     
做好准备吧。
  7   
我就是为了说出这件事，才来这里的。
     CreateEyelids     CreateCameraOrtho     カメラ01     SCREEN_WIDTH     SCREEN_HEIGHT     RandomShakeStart3D     XBg01A  ;   cg/ep/sl/xbg003030_12_学園生徒会室入り口側_b1.png     Move3D  	   SetCamera     FadeDeleteBg  ;   
#{・・・・・・・・}我向她说出了事实#。
  ;   
//【種崎捨】
「之后，检查结果出来了」
  ,   
//【種崎捨】
「基因不一致」
  5   
//【種崎捨】
「我们没有血缘关系」
  /   
//【種崎捨】
「没有任何关系」
  �   
//【許斐鳴子】
<voice name='許斐鳴子' class='許斐鳴子' src='voice/f51/9100020a05'>
「不。不是那样的」
     se人体_動作_心臓02     CreateSprite     BgCopy     SCREEN     SetShadingPower     SHADE_LEVE_HIGH     
心跳加快。
  .   
我拼命克制住惊恐尖叫的冲动。
     
她真实的想法，
     
是——
     SceneEndTRAP     thisTRAPTRAP     this        m  TRAP&       (       -      .   	   /      1      3      4      6      7   &   :   &   ;   ,   =   /   >   3   @   6   L   9   M   <   P   @   R   D   S   G   T   L   V   O   W   S   X   ^   Y   a   \   d   ]   g   `   k   b   o   e   r   f   u   k   y   n   }   o   �   s   �   u   �   v   �   x   �   y   �   z   �   }   �   ~   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �   �     �     �   	  �     �     �     �     �     �     �   "  �   &  �   *  �   -  �   1  �   5  �   8  �   <  �   @  �   C  �   G  �   K  �   N  �   R  �   V  �   Y  �   ^  �   a  �   e  �   p  �   v  �   y  �   |  �   �  �   �  �   �  �   �  �   �  �   �     �    �    �    �    �    �    �    �    �    �    �    �    �    �  !  �  "  �  &  �  (  �  +  �  ,  �  0  �  4  �  5  �  9  �  =  �  >    B    E  
  H    I    N    P    Q    S     T  '  U  0  V  3  W  9  Z  <  [  ?  ^  C  a  G  b  J  e  N  h  R  i  U  l  Y  o  ]  p  `  s  d  u  h  �  k  �  m  TRAPTRAP           	     �   ,           
                 N                     F        	    
          
                      �            	              �                            
     �                      �              <            �           �                        
                 ,            	                         �           �              2                 �                   +              +            �           �                                         ,                �                                         ,                             (                 ,            	                         �               (            �           �                        2     !            ,                             <     "            ,            	       #                  �          �             	     $    %     �    &   	     '    %     �    �                     �                        F     (            ,            	    )   *       )           �                        P     +            ,            	    ,   -       ,                  .           �       /    0     �    1   	  2   	  3            %     �                 4    5            �                        Z     6            ,                             d     7            ,                             n     8            ,                             x     9            ,                             �     :            ,                             �     ;            ,                             �     <            ,            	       =                  �           �              d                 �                   +              +>            0     �                     �                        �     ?            ,                             �     @            ,                             �     A            ,                �       B       C    D                 �       -  E   	  F   	     	  �  
     	G    D        /    H     
     1   	  �       -  I        J    H                         +              +
        -          	      
     	K    H   D   L    �           �                        �     M            ,                �                        �     N            ,                �                        �     O            ,                             �     P            ,                             �     Q            ,                �                        �     R            ,            	       S                  �       T    U     �    1   	  2   	  V        W    U     �     �    X   	  d              	         �           U     �                      �                            Y            ,                                 Z            ,                                 [            ,                             "    \            ,                �       ]           �  TRAP          LIAT    