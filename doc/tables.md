##数据库设计##

###用户表###
用户ID(*主键*)    
姓名    
个人头像    
邮箱    
手机    
密码    
用户类型(*0*:*管理员* *1*:*普通用户* *2*:*达人* *4*:*驻站作者* *8*:*明星用户*)    
个人简介    
注册时间    
注销标志    
注销时间    
诗歌评论    
诗歌集评论    
喜欢的作者    
收藏诗歌    
关注自己的朋友    
自己关注的朋友    
录入作品列表    

###审批用户表###
审批ID(*主键*)    
审批用户ID(*外键*:*用户表ID*)    
申请内容   
补充内容    
状态(*0*:*申请* *1*:*受理* *2*:*处理中* *4*:*通过* *8*:*拒绝*)      
审批者ID(*外键*:*用户ID*)    
审批意见    
审批通过时间    

###好友表###
ID(*主键*)    
用户表ID(*外键*:*用户表ID*)    
用户表ID(*外键*:*用户表ID*)    
关注时间    

###作品类型表###
作品类型ID(*主键*)    
类型名称    
作品列表    

###作者表###
作者ID(*主键*)    
作者拼音    
作者姓名    
出生年月    
性别    
国籍    
作者图片    
作者简介    
作者作品列表    
      
###作品表###
作品ID(*主键*)    
作品名    
作者ID(*外键 索引 作者表ID*)    
作品类型ID:(*外键 作品类型表ID*)    
作品内容    
录入者(*外键 用户表ID*)    
录入时间    
收藏数    
评论列表      

###收藏表（喜欢的诗歌）###
收藏ID(*外键 用户表ID*)   
诗歌ID(*外键 作品表ID*)   
收藏时间     
    
###喜欢的作者表###
喜欢作者的ID(*外键 用户表ID*)    
作者ID(*外键 作者表ID*)    
喜欢的时间   

###诗集表###
诗集ID(*主键*)  
创建者ID(*外键 用户表ID*)    
诗集名称    
诗集简介    
诗集封面图像    
创建时间    
诗歌集评论    
诗集作品详细        

###诗集作品详细表###
诗集ID(*外键 外键 诗集表ID*)    
诗歌ID(*外键 外键 诗歌表ID*)    
添加时间

###诗集评论表###
评论ID(*主键*)  
诗集ID(*外键 诗集表ID*)    
评论者ID(*外键 用户ID*)    
评论内容    
评论时间    

###诗歌评论表###
评论ID(*主键*)  
诗歌ID(*外键 诗歌表ID*)    
评论者ID(*外键 用户ID*)    
评论内容    
评论时间    